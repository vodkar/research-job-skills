# Research job skills

## Example runs

1. HeadHunter only (fastest start):

```
python appsec_skill_miner.py \
  --source hh \
  --query "appsec" \
  --query "application security" \
  --query "безопасность приложений" \
  --query "инженер по безопасности приложений" \
  --days 365 \
  --max-pages 20 \
  --out-dir out_hh
```

1. HeadHunter + SuperJob:

```
export SUPERJOB_API_KEY="YOUR_SUPERJOB_KEY"
python appsec_skill_miner.py \
  --source hh --source superjob \
  --query "appsec" --query "безопасность приложений" \
  --days 365 \
  --max-pages 20 \
  --out-dir out_hh_sj
```

1. Add Trudvsem:

```
python appsec_skill_miner.py \
  --source trudvsem \
  --query "appsec" \
  --query "application security" \
  --query "безопасность приложений" \
  --query "инженер по безопасности приложений" \
  --query "информационная безопасность" \
  --query "безопасность приложений" \
  --out-dir out_with_trudvsem
```
