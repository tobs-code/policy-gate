/**
 * policy-gate — TypeScript wrapper
 *
 * This wrapper provides the Node.js-facing API.
 * The actual safety function runs in the Rust core (loaded via napi-rs).
 *
 * Architecture note:
 *   The Rust core is the safety-critical boundary.
 *   This TS layer is NOT part of the safety function — it handles:
 *     • Input marshalling / type coercion
 *     • Async scheduling (never blocks the event loop)
 *     • Audit log persistence (caller responsibility)
 *     • Error reporting to the application layer
 *
 * Usage:
 *   import { Firewall } from 'policy-gate';
 *   const fw = await Firewall.create();
 *   const verdict = await fw.evaluate("What is the capital of France?");
 *   if (!verdict.isPass) throw new Error(`Blocked: ${verdict.blockReason}`);
 */

// ─── Types (mirrors Rust types.rs) ───────────────────────────────────────────

export type VerdictKind =
  | 'Pass'
  | 'Block'
  | 'DiagnosticAgreement'
  | 'DiagnosticDisagreement'
  | 'EgressBlock';

export type MatchedIntent =
  | 'QuestionFactual'
  | 'QuestionCausal'
  | 'QuestionComparative'
  | 'TaskCodeGeneration'
  | 'TaskTextSummarisation'
  | 'TaskTranslation'
  | 'TaskDataExtraction'
  | 'ConversationalGreeting'
  | 'ConversationalAcknowledgement'
  | 'SystemMetaQuery';

export type BlockReason =
  | { type: 'NoIntentMatch' }
  | { type: 'ForbiddenPattern'; patternId: string }
  | { type: 'ExceededMaxLength' }
  | { type: 'WatchdogTimeout' }
  | { type: 'MalformedInput'; detail: string };

export interface ChannelResult {
  channel: 'A' | 'B';
  decision:
    | { type: 'Pass'; intent: MatchedIntent }
    | { type: 'Block'; reason: BlockReason }
    | { type: 'Fault'; code: string };
  elapsedUs: number;
}

export interface AuditEntry {
  sequence: number;
  ingestedAtNs: bigint;
  decidedAtNs: bigint;
  totalElapsedUs: number;
  verdictKind: VerdictKind;
  /** SHA-256 hex of normalised input. Never log the raw input in production. */
  inputHash: string;
}

export interface Verdict {
  kind: VerdictKind;
  /** True iff the prompt is permitted to proceed to the LLM. */
  isPass: boolean;
  channelA: ChannelResult;
  channelB: ChannelResult;
  audit: AuditEntry;
  /** Populated for blocking verdicts. */
  blockReason?: string;
}

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ConversationVerdict {
  isPass: boolean;
  firstBlockIndex: number | null;
  verdicts: Verdict[];
}

export interface EgressVerdict {
  kind: 'Pass' | 'EgressBlock';
  isPass: boolean;
  egressReason?: string;
  audit?: Pick<AuditEntry, 'sequence' | 'inputHash'>;
}

// ─── Firewall class ───────────────────────────────────────────────────────────

export interface FirewallOptions {
  /**
   * Optional async function to persist audit entries.
   * Called after EVERY evaluation, including blocks.
   * If this throws, the error is logged but does NOT affect the verdict.
   * The caller is responsible for audit durability.
   */
  onAudit?: (entry: AuditEntry) => Promise<void>;

  /**
   * Optional async function called on DiagnosticDisagreement events.
   * These require human review within the timeframe specified in Safety Manual §8.
   */
  onDisagreement?: (verdict: Verdict) => Promise<void>;
}

export class Firewall {
  private sequence = 0n;
  private opts: FirewallOptions;
  // The native module handle (napi-rs compiled Rust core)
  private native: NativeFirewall;

  private constructor(native: NativeFirewall, opts: FirewallOptions) {
    this.native = native;
    this.opts = opts;
  }

  /**
   * Factory method — must be used instead of constructor.
   * Runs the Rust startup self-test before accepting any input.
   * Throws FirewallInitError if the self-test fails.
   */
  static async create(opts: FirewallOptions = {}): Promise<Firewall> {
    const native = await loadNative();
    const initResult = native.init();
    if (initResult !== null) {
      throw new FirewallInitError(`Rust core self-test failed: ${initResult}`);
    }
    return new Firewall(native, opts);
  }

  /**
   * Evaluate a prompt through the 1oo2D safety gate.
   *
   * @param text  Raw prompt text (will be normalised by Rust core)
   * @param role  Optional role tag ("user" | "system" | "tool")
   * @returns     Verdict — check isPass before forwarding to LLM
   */
  async evaluate(text: string, role?: string): Promise<Verdict> {
    const seq = Number(this.sequence++);

    // All evaluation happens in the Rust core (off the event loop via napi-rs worker thread)
    const rawVerdict = await this.native.evaluate({ text, role: role ?? undefined, sequence: seq });
    const verdict = mapVerdict(rawVerdict);

    // Async side-effects (non-blocking, non-safety-critical)
    if (this.opts.onAudit) {
      this.opts.onAudit(verdict.audit).catch(err => {
        console.error('[firewall] audit callback error:', err);
      });
    }

    if (
      verdict.kind === 'DiagnosticDisagreement' &&
      this.opts.onDisagreement
    ) {
      this.opts.onDisagreement(verdict).catch(err => {
        console.error('[firewall] disagreement callback error:', err);
      });
    }

    return verdict;
  }

  /**
   * Evaluate a multi-message conversation with the core sliding-window checks.
   */
  async evaluateMessages(messages: ChatMessage[]): Promise<ConversationVerdict> {
    const baseSequence = Number(this.sequence);
    this.sequence += BigInt(messages.length);

    const rawConversation = await this.native.evaluateMessages(messages, baseSequence);
    const verdicts = rawConversation.verdicts.map(mapVerdict);

    for (const verdict of verdicts) {
      if (this.opts.onAudit) {
        this.opts.onAudit(verdict.audit).catch(err => {
          console.error('[firewall] audit callback error:', err);
        });
      }

      if (
        verdict.kind === 'DiagnosticDisagreement' &&
        this.opts.onDisagreement
      ) {
        this.opts.onDisagreement(verdict).catch(err => {
          console.error('[firewall] disagreement callback error:', err);
        });
      }
    }

    return {
      isPass: rawConversation.isPass,
      firstBlockIndex:
        rawConversation.firstBlockIndex >= 0 ? rawConversation.firstBlockIndex : null,
      verdicts,
    };
  }

  /**
   * Evaluate an LLM response against the original prompt to detect leakage/PII.
   */
  async evaluateOutput(prompt: string, response: string): Promise<EgressVerdict> {
    const seq = Number(this.sequence++);
    const raw = await this.native.evaluateOutput(prompt, response, seq);
    return {
      kind: raw.kind,
      isPass: raw.isPass,
      egressReason: raw.egressReason || undefined,
      audit: raw.inputHash
        ? {
            sequence: raw.sequence,
            inputHash: raw.inputHash,
          }
        : undefined,
    };
  }
}

// ─── Error types ─────────────────────────────────────────────────────────────

export class FirewallInitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallInitError';
  }
}

export class FirewallEvaluationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallEvaluationError';
  }
}

// ─── Internal: native module loading ─────────────────────────────────────────

interface NativeFirewall {
  init(): string | null;
  evaluate(input: { text: string; role?: string; sequence: number }): Promise<RawVerdict>;
  evaluateMessages(messages: ChatMessage[], baseSequence: number): Promise<RawConversationVerdict>;
  evaluateOutput(prompt: string, response: string, sequence: number): Promise<RawEgressVerdict>;
}

interface RawVerdict {
  kind: VerdictKind;
  channelA?: ChannelResult;
  channelB?: ChannelResult;
  channelADecision?: string;
  channelBDecision?: string;
  elapsedUs?: number;
  inputHash?: string;
  sequence?: number;
  blockReason?: string;
  audit?: {
    sequence: number;
    ingestedAtNs: bigint;
    decidedAtNs: bigint;
    totalElapsedUs: number;
    verdictKind: VerdictKind;
    inputHash: string;
  };
}

interface RawConversationVerdict {
  isPass: boolean;
  firstBlockIndex: number;
  verdicts: RawVerdict[];
}

interface RawEgressVerdict {
  kind: 'Pass' | 'EgressBlock';
  isPass: boolean;
  egressReason: string;
  inputHash: string;
  sequence: number;
}

async function loadNative(): Promise<NativeFirewall> {
  // napi-rs generates this binding automatically from Cargo.toml.
  // During development, fall back to a mock if the native module isn't compiled yet.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const native = require('../native/index.node');
    return {
      init: native.firewallInit.bind(native),
      evaluate: native.firewallEvaluate.bind(native),
      evaluateMessages: native.firewallEvaluateMessages.bind(native),
      evaluateOutput: native.firewallEvaluateOutput.bind(native),
    };
  } catch {
    console.warn('[firewall] Native module not found — using development stub');
    return devStub();
  }
}

function mapVerdict(raw: RawVerdict): Verdict {
  const audit = raw.audit ?? {
    sequence: raw.sequence ?? 0,
    ingestedAtNs: 0n,
    decidedAtNs: 0n,
    totalElapsedUs: raw.elapsedUs ?? 0,
    verdictKind: raw.kind,
    inputHash: raw.inputHash ?? '',
  };
  const channelA = raw.channelA ?? parseStableChannelDecision('A', raw.channelADecision ?? 'Fault:InternalPanic', raw.elapsedUs ?? audit.totalElapsedUs, raw.blockReason);
  const channelB = raw.channelB ?? parseStableChannelDecision('B', raw.channelBDecision ?? 'Fault:InternalPanic', raw.elapsedUs ?? audit.totalElapsedUs, raw.blockReason);

  return {
    kind: raw.kind,
    isPass: raw.kind === 'Pass' || raw.kind === 'DiagnosticAgreement',
    channelA,
    channelB,
    audit,
    blockReason:
      raw.kind === 'Block' || raw.kind === 'DiagnosticDisagreement'
        ? raw.blockReason
          || formatBlockReasonFromDecision(channelA.decision)
          || formatBlockReasonFromDecision(channelB.decision)
        : undefined,
  };
}

function parseStableChannelDecision(
  channel: 'A' | 'B',
  value: string,
  elapsedUs: number,
  fallbackBlockReason?: string,
): ChannelResult {
  const [kind, ...rest] = value.split(':');
  const payload = rest.join(':');

  if (kind === 'Pass') {
    return {
      channel,
      decision: {
        type: 'Pass',
        intent: payload as MatchedIntent,
      },
      elapsedUs,
    };
  }

  if (kind === 'Fault') {
    return {
      channel,
      decision: {
        type: 'Fault',
        code: payload,
      },
      elapsedUs,
    };
  }

  return {
    channel,
    decision: {
      type: 'Block',
      reason: parseStableBlockReason(payload || fallbackBlockReason || 'NoIntentMatch'),
    },
    elapsedUs,
  };
}

function parseStableBlockReason(value: string): BlockReason {
  const [kind, ...rest] = value.split(':');
  const payload = rest.join(':');

  switch (kind) {
    case 'ForbiddenPattern':
      return { type: 'ForbiddenPattern', patternId: payload };
    case 'MalformedInput':
      return { type: 'MalformedInput', detail: payload };
    case 'ExceededMaxLength':
      return { type: 'ExceededMaxLength' };
    case 'WatchdogTimeout':
      return { type: 'WatchdogTimeout' };
    case 'NoIntentMatch':
    default:
      return { type: 'NoIntentMatch' };
  }
}

function formatBlockReasonFromDecision(decision: ChannelResult['decision']): string | undefined {
  if (decision.type !== 'Block') {
    return undefined;
  }

  const reason = decision.reason;
  switch (reason.type) {
    case 'ForbiddenPattern':
      return `${reason.type}:${reason.patternId}`;
    case 'MalformedInput':
      return `${reason.type}:${reason.detail}`;
    default:
      return reason.type;
  }
}

// ─── Dev stub (NOT for production) ───────────────────────────────────────────
// Allows TS development before the Rust core is compiled.
// The stub is deterministically BLOCK-heavy to mirror the fail-closed default.

function devStub(): NativeFirewall {
  return {
    init: () => null,
    evaluate: async (input) => {
      const passPatterns = [/\?$/, /^(hi|hello|hey)/i, /\b(write|create|generate)\b.*\b(function|code)\b/i];
      const isPass = passPatterns.some(p => p.test(input.text));
      const now = BigInt(Date.now()) * 1_000_000n;
      return {
        kind: isPass ? 'Pass' : 'Block',
        channelA: {
          channel: 'A',
          decision: isPass
            ? { type: 'Pass', intent: 'QuestionFactual' }
            : { type: 'Block', reason: { type: 'NoIntentMatch' } },
          elapsedUs: 12,
        },
        channelB: {
          channel: 'B',
          decision: isPass
            ? { type: 'Pass', intent: 'QuestionFactual' }
            : { type: 'Block', reason: { type: 'NoIntentMatch' } },
          elapsedUs: 8,
        },
        audit: {
          sequence: input.sequence,
          ingestedAtNs: now,
          decidedAtNs: now + 20_000n,
          totalElapsedUs: 20,
          verdictKind: isPass ? 'Pass' : 'Block',
          inputHash: `stub-${input.text.length}`,
        },
      };
    },
    evaluateMessages: async (messages, baseSequence) => {
      const verdicts = await Promise.all(
        messages.map((message, index) =>
          devStub().evaluate({
            text: message.content,
            role: message.role,
            sequence: baseSequence + index,
          }),
        ),
      );
      const firstBlocked = verdicts.findIndex(v => v.kind === 'Block' || v.kind === 'DiagnosticDisagreement');
      return {
        isPass: firstBlocked === -1,
        firstBlockIndex: firstBlocked,
        verdicts: firstBlocked === -1 ? verdicts : verdicts.slice(0, firstBlocked + 1),
      };
    },
    evaluateOutput: async (prompt, response, sequence) => {
      const leaked = response.toLowerCase().includes('system prompt') || response.includes(prompt.slice(0, 20));
      return {
        kind: leaked ? 'EgressBlock' : 'Pass',
        isPass: !leaked,
        egressReason: leaked ? 'SystemPromptLeakage:stub-detected' : '',
        inputHash: `stub-${prompt.length}`,
        sequence,
      };
    },
  };
}
