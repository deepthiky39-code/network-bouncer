# GitHub Push Instructions

## Problem
The git history contains large dataset files (400MB) that are causing push failures.

## Solution: Fresh Push Without History

Run these commands to push the code without the large file history:

```bash
# 1. Remove the old git repository
Remove-Item -Recurse -Force .git

# 2. Initialize fresh repository
git init
git add .
git commit -m "Complete Network Bouncer implementation

- Core detection engine with 3 threshold rules
- Time-window burst detection
- Severity scoring (0-100)
- Risk level classification (severity-based)
- Problem statement format output
- CSV reports and 3 visualization charts
- 96 automated tests (100% passing)
- UNSW-NB15 dataset support
- Faculty presentation guides
- Processed 2.5M records successfully"

# 3. Add remote and push
git branch -M main
git remote add origin https://github.com/deepthiky39-code/network-bouncer.git
git push -u origin main --force
```

## What Gets Pushed
✅ All source code (network_bouncer/*.py)
✅ All tests (tests/*.py)  
✅ Demo script (create_demo_dataset.py)
✅ Prep script (prepare_unsw_data.py)
✅ Documentation (README.md, guides)
✅ Requirements (requirements.txt)
✅ .gitignore (excludes large files)

## What Gets Excluded (via .gitignore)
❌ Large CSV datasets (download separately from UNSW-NB15)
❌ Generated outputs (*.png, *.csv)
❌ Cache files (__pycache__, .pytest_cache)

## Note for Users
Users can download the UNSW-NB15 dataset from:
https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15

Then run:
```bash
python prepare_unsw_data.py
python -m network_bouncer.main unsw_nb15_full.csv
```
