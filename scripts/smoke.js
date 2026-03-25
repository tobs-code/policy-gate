'use strict';

async function main() {
  const { Firewall } = require('../dist/index.js');

  const fw = await Firewall.create();
  const verdict = await fw.evaluate('What is the capital of France?');
  const conversation = await fw.evaluateMessages([
    { role: 'user', content: 'Hello!' },
    { role: 'user', content: 'What is the capital of France?' }
  ]);
  const egress = await fw.evaluateOutput(
    'What is the capital of France?',
    'The capital of France is Paris.'
  );

  console.log(JSON.stringify({
    evaluate: verdict.kind,
    conversation: {
      isPass: conversation.isPass,
      verdictCount: conversation.verdicts.length
    },
    egress: egress.kind
  }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
