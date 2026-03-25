'use strict';

const fs = require('fs');
const path = require('path');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  const corpusPath = path.join(__dirname, '..', 'verification', 'conformance_corpus.json');
  const corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
  const { Firewall } = require('../dist/index.js');

  const fw = await Firewall.create();

  for (const testCase of corpus.single) {
    const verdict = await fw.evaluate(testCase.input);
    assert(
      verdict.kind === testCase.expected_kind,
      `single:${testCase.name} expected ${testCase.expected_kind}, got ${verdict.kind}`
    );
  }

  for (const testCase of corpus.conversation) {
    const verdict = await fw.evaluateMessages(testCase.messages);
    assert(
      verdict.isPass === testCase.expected_is_pass,
      `conversation:${testCase.name} expected isPass=${testCase.expected_is_pass}, got ${verdict.isPass}`
    );
    assert(
      verdict.firstBlockIndex === testCase.expected_first_block_index,
      `conversation:${testCase.name} expected firstBlockIndex=${testCase.expected_first_block_index}, got ${verdict.firstBlockIndex}`
    );
  }

  for (const testCase of corpus.egress) {
    const verdict = await fw.evaluateOutput(testCase.prompt, testCase.response);
    assert(
      verdict.kind === testCase.expected_kind,
      `egress:${testCase.name} expected ${testCase.expected_kind}, got ${verdict.kind}`
    );
  }

  console.log(JSON.stringify({
    status: 'ok',
    single: corpus.single.length,
    conversation: corpus.conversation.length,
    egress: corpus.egress.length
  }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
