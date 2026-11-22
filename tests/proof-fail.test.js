// Deliberately failing test: proves a red check blocks merging. This PR is closed without merging.
require("node:test")("deliberate failure (proof, do not merge)", () => { require("node:assert").equal(1, 2); });
