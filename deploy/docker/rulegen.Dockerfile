# Image for the autonomous rule-generation loop (F11), run as a CronJob. It carries the compiler,
# the curated + generated rule library and a labeled trace corpus; each run mines/ingests, links a
# bundle and PUTs it to the console (control plane) so agents hot-swap it. CPU-only, no LLM.
FROM python:3.12-slim
WORKDIR /app

COPY compiler /app/compiler
# The fleet corpus (benign baseline + honeypot/attack) is the novelty-mining source; it is a dir of
# labeled *.jsonl, which trace.load reads directly.
COPY testdata/traces/fleet /app/corpus
RUN pip install --no-cache-dir ./compiler

# Defaults; the CronJob overrides --console (and may add --feeds).
ENTRYPOINT ["ariguard-rulegen-loop"]
CMD ["--rules-dir=/app/compiler/rules", "--sigma-dir=/app/compiler/rules/sigma/generated", "--corpus=/app/corpus"]
