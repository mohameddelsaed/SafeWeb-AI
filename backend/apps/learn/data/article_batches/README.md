# Article Batches

This folder stores staged content batches for Learning Center ingestion.

## Conventions
- Use JSON arrays for each batch file.
- Keep each batch between 50 and 100 articles for safer review.
- Each article should include references, security mappings, and difficulty level.
- Use rewritten synthesis from authoritative sources; do not copy source text.

## Suggested Workflow
1. Draft outlines in `outlines_*.json`.
2. Generate draft articles with management commands.
3. Validate batches with `validate_articles` command.
4. Enforce score gate in CI with `--strict --min-score 75`.
5. Bulk import with `bulk_load_articles` command in dry-run mode first.
6. Publish in phases with `publish_articles --min-quality-score 75` after editorial QA.

## 500-Article Program Assets
- `learning_center_500_execution_plan.md`: source policy, level distribution, and batch strategy.
- `outlines_master_500.json`: 500 beginner-to-expert outlines aligned to taxonomy.
- `outlines_program_batch_001.json` ... `outlines_program_batch_010.json`: 10 outline batches (50 each).
- `generated_program_batch_001.json` ... `generated_program_batch_010.json`: 10 generated draft batches (50 each, total 500).

## Reproducible Commands
```bash
# Generate one draft batch from one outline batch
cd backend
python manage.py generate_article_drafts \
	--outlines apps/learn/data/article_batches/outlines_program_batch_001.json \
	--output apps/learn/data/article_batches/generated_program_batch_001.json \
	--author "Security Team"

# Validate one generated batch with strict quality gate
python manage.py validate_articles \
	--source apps/learn/data/article_batches/generated_program_batch_001.json \
	--strict --min-score 75

# Dry-run bulk load to verify insertion safety
python manage.py bulk_load_articles \
	--source apps/learn/data/article_batches/generated_program_batch_001.json \
	--dry-run --skip-duplicates
```
