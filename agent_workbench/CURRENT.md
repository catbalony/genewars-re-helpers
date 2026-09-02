# CURRENT - start here

You are an external research worker for the catbalony GeneWars
reverse-engineering project. This file is the one stable entry point.

1. Read the protocol: [protocol/README.md](protocol/README.md) - it defines
   what you may claim and how to label it (OBSERVATION / INFERENCE /
   HYPOTHESIS; never PROVEN; return a useful PARTIAL early if time runs
   out).
2. Work the batch listed under **Published batches** below. Each batch
   folder contains `batch.json` (task, expected output format, evidence
   manifest) and `prompt.txt` (your exact task, including the mandatory
   briefing).
3. Evidence references point at material that already exists in this
   repository (symbols, XML, bytes). Nothing is asked of you that requires
   private data.
4. Return your response in the format the batch's `output_expectations`
   names. Your response is preserved byte-for-byte by the private side and
   validated before anything else happens to it.

Remember: your output is research input, never proof authority.

## Published batches

- `bw-c59498e516c3`
