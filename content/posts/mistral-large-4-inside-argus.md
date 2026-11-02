Title: Three Models, One Codebase: Mistral Large 4 Inside Argus Systems
Date: 2026-11-02
Slug: mistral-large-4-inside-argus
Author: Mehrun P. Hunter and Shahriyar Jalayeri
Category: Product
Tags: argus, mistral, mistral-large-4, glm, deepseek, php, llm, evaluation
Summary: We gave PHP's source code to Argus Systems three times and swapped the model each run: Mistral Large 4, Z.ai GLM 5.3 and DeepSeek V4 Pro. Mistral Large 4 covered the most code, ran the deep stages most often and returned the most Critical and High findings. It also grades hot and writes long, and we want to talk about both.

Most posts on this blog are about one bug, followed from the line of code to the crash. This one is about what happened when we gave the same job to three models and watched how each of them worked.

The job was PHP's source code. The harness was Argus Systems, our autonomous product security platform. Argus runs every stage of an investigation, from the first look at a package through variant hunting, tracing, adversarial review, write up, proof of concept and fix, and it keeps the evidence at each step. The model does the thinking, and nothing else changes between runs. That makes Argus a good place to swap one model for another and see what moves.

We ran it three times: once with Mistral Large 4, once with Z.ai GLM 5.3, once with DeepSeek V4 Pro. Same copy of PHP, same pipeline, a different model at the wheel.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-how-the-test-ran.png" alt="Flow diagram: PHP source code into the Argus Systems harness, with one of three models swapped in, producing findings and evidence. Below it, the nine pipeline stages." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 1.</strong> How the test ran. One identical copy of PHP's source code goes into Argus Systems, which runs all nine stages (Explore, Distiller, VRE, Variants, Trace, Adversarial review, Write up, PoC, Fix) and swaps in Mistral Large 4, Z.ai GLM 5.3 or DeepSeek V4 Pro for the reasoning. The output is severity grades, PoCs that trigger each flaw, and proposed fixes. Argus is proprietary, so not every detail of the harness is shown.</figcaption>
</figure>

We expected Mistral Large 4 to be the quick, inexpensive option and not much more. The first half of that was right.

## What it found

Mistral and Z.ai worked almost the same number of hours, 17h 19m against 17h 56m. In that time Mistral finished 174 of its 184 checks, 10.05 an hour. Z.ai finished 138 of 139 at 7.69 an hour. DeepSeek, working from a much longer check list, got through 56 of 658 in 14 hours.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-working-hours.png" alt="Table with a working-time bar per model, checks per hour, and counts of Critical, High, Medium and Low findings." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 2.</strong> Working hours and findings by severity. Mistral: 174 of 184 checks in 17h 19m (10.05 per hour), 12 Critical, 60 High, 57 Medium, 123 Low. Z.ai: 138 of 139 checks in 17h 56m (7.69 per hour), 1 Critical, 51 High, 90 Medium, 188 Low. DeepSeek: 56 of 658 checks in 14h 02m (3.99 per hour), 0 Critical, 24 High, 31 Medium, 24 Low.</figcaption>
</figure>

Severity is where Mistral pulled away. It returned 12 Critical and 60 High findings, 72 in total. Z.ai returned 1 Critical and 51 High. DeepSeek returned no Criticals and 24 Highs. Per hour of work, that is 3.93 serious findings from Mistral, 1.18 from Z.ai and 1.50 from DeepSeek.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-critical-high.png" alt="Stacked bars of findings per model split by Critical, High, Medium and Low, with the Critical plus High total to the right, and three summary figures for Mistral's 72 below." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 3.</strong> Findings by severity, with the Critical plus High total for each model. Mistral 252 findings, 72 serious (12 Critical, 60 High). Z.ai 330 findings, 52 serious (1 Critical, 51 High). DeepSeek 79 findings, 24 serious (0 Critical, 24 High). The bottom row puts Mistral's 72 three ways: 28.6% of its findings, 41.4 per 100 completed checks, and 3.93 per hour, the highest rate of the three.</figcaption>
</figure>

## It went deeper, not only wider

The stage counts are the chart we keep going back to. Argus does not run the late stages on every lead. A variant hunt, a trace and a round of adversarial review happen when the model decides the lead is worth it. Mistral decided that far more often: 121 variant hunts to Z.ai's 68, 121 traces to 49, 120 adversarial review rounds to 65. The later the stage, the wider the gap.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-depth.png" alt="Grouped bar chart of how many times Argus ran each pipeline stage per model." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 4.</strong> How many times Argus ran each stage, per model. Explore: Mistral 183, Z.ai 139, DeepSeek 70. VRE: 182, 139, 67. Variants: 121, 68, 49. Trace: 121, 49, 51. Adversarial review: 120, 65, 49. Write up: 119, 67, 52. Against Z.ai, Mistral ran 78% more variant hunts, 147% more traces and 85% more adversarial review rounds.</figcaption>
</figure>

The three runs together produced 103 advisories against 99 root causes, and 90 of those root causes came from one model alone. Mistral on its own accounted for 37 advisory files and 35 root causes that neither of the others reached. Only four files were found by all three. If you ever needed an argument for running more than one model over the same code, this Venn diagram is it.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-who-found-what.png" alt="Left: Venn diagram of advisory files found by each model and their overlaps. Right: raw findings versus findings kept after review, per model." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 5.</strong> Who found what. The circles count advisory files: Mistral only 37, Z.ai only 47, DeepSeek only 6, Mistral and Z.ai 7, Mistral and DeepSeek 2, Z.ai and DeepSeek 0, all three 4. The 37 Mistral-only files map to 35 root causes and the four shared files to 2; every other region is one root cause per file. On the right, raw findings against what survived adversarial review: Mistral 1,051 raw, 451 kept (43%). Z.ai 439 raw, 332 kept (76%). DeepSeek 205 raw, 81 kept (40%).</figcaption>
</figure>

## Where it needs a hand

Mistral Large 4 is quick and it is talkative. It produced 1,051 raw findings, more than the other two combined, and it wrote each one up at length. Adversarial review kept 451 of them, 43%. Z.ai's pile was a third of the size and review kept 76% of it. Of the findings Mistral itself marked as confirmed, 10.3% were later judged non-viable. For Z.ai that figure was 1.5%.

The pattern behind those numbers is a model that grades hot. A Medium gets written up as a High, a plausible path gets written up as a confirmed one, and the report is long enough that a reader could mistake confidence for evidence. It spends the least inference time of the three on verifying its own claims. It also likes to come back to the same spot from a new angle: 63% of its findings landed on a distinct file and function, against 86% for Z.ai, and 83.9% of its candidates were variants of something it had already seen. That habit is part of why it finds so much. It is also why review has work to do afterwards.

<figure style="max-width: 820px; margin: 1.5rem auto;">
<img src="{attach}/attachments/ml4-behaviour.png" alt="Six comparison rows, each with the three models' values and a slider placing them between two poles." style="width: 100%; height: auto; display: block;">
<figcaption style="font-size: 0.9rem; color: #555; margin-top: 0.5rem; line-height: 1.45;"><strong>Figure 6.</strong> Six behaviour measures, in the order Mistral Large 4 (orange), Z.ai GLM 5.3 (dark blue), DeepSeek V4 Pro (grey). Findings per hour 19.4, 10.1, 13.1. Packages covered 194, 93, 39. Report rows kept after review 42.9%, 75.6%, 39.5%. Confirmed findings later judged non-viable 10.3%, 1.5%, 3.7%. Variant-style candidates 83.9%, 71.5%, 77.1%. Findings on a distinct file and function 63%, 86%, 82%.</figcaption>
</figure>

Inside Argus this costs us very little. Root causes are merged automatically and every distinct flaw has to pass a dynamic PoC gate before anyone reads the advisory. The gate is cheap, so Mistral's extra claims are a few minutes of compute rather than a day of an analyst's time. Outside a harness like that, you would feel every one of them.

If anyone at Mistral is reading: the coverage, the stamina across many independent checks and the appetite for the deep stages are the hard part, and you have them. A calmer severity scale and shorter write ups would make this a model that is very hard to argue with.

## Why it still won

The metric we care about is cost and time per validated finding. On that measure, inside Argus, Mistral Large 4 came first. It optimises for speed, cost and coverage, and leaves verification to sit outside the model. Z.ai GLM 5.3 is the one to pick when you cannot afford to verify, because most of what it says is true the first time. DeepSeek V4 Pro thinks hardest per problem, and the throughput paid for it in this run.

Two caveats before anyone quotes this as a benchmark. These are three runs, one each, on one codebase, with check lists that were not identical. A controlled comparison would need matched guidance, matched time budgets and repeats. And a seventeen hour scan is not proof of a seventeen hour attention span: Argus splits the work into many independent checks, and the stamina we saw was stamina across checks, not within one.

What we can say is what we saw. We put a model we had filed under "cheap and fast" into the harness, and it came out with the most serious findings, the most unique root causes and the deepest stage counts of the three. That was a good week.
