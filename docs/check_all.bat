@echo off
REM ============================================================
REM  One-click pipeline check for ScanMan (CPU only)
REM  Usage:  double-click, or run  docs\check_all.bat  from anywhere
REM  NOTE: keep this file ASCII-only so cmd does not garble it.
REM ============================================================
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

REM cd to project root (this file lives in <root>\docs\)
cd /d "%~dp0.."
set PYTHONPATH=%CD%

REM Pick an interpreter: project venv -> whatever is on PATH
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo [WARN] .venv not found, falling back to "python" on PATH.
    echo        Create one with:  python -m venv .venv
    set "PY=python"
)
echo Using interpreter: %PY%
echo.

REM ---- Prerequisites: models/ and data/processed/ are gitignored, so a fresh
REM ---- clone will NOT have them. Fail here with a clear message instead of
REM ---- dying at step 4 with a confusing error.
set "PREREQ_OK=1"
if not exist "models\microsoft__codebert-base" (
    echo [FAIL] Missing base model: models\microsoft__codebert-base
    echo        Get it with:  %PY% scripts\download_model.py --models codebert
    set "PREREQ_OK="
)
if not exist "data\processed\cvefixes_detection_train.jsonl" (
    echo [FAIL] Missing training data: data\processed\cvefixes_detection_train.jsonl
    echo        Build it with:  %PY% scripts\download_data.py --datasets cvefixes
    echo                        %PY% scripts\build_dataset.py --source cvefixes
    set "PREREQ_OK="
)
if not defined PREREQ_OK (
    echo.
    echo See docs\README.md, section "Fastest way to verify" (heading is in Chinese), for details.
    pause
    exit /b 2
)
echo Prerequisites OK.
echo.

echo ============================================================
echo  1/5  Environment check
echo ============================================================
%PY% scripts\check_env.py || goto :fail

echo ============================================================
echo  2/5  Unit tests (tests/)
echo ============================================================
%PY% -m pytest tests\ -q || goto :fail

echo ============================================================
echo  3/5  Preprocess assertions (docs/test_cases)
echo ============================================================
%PY% docs\test_cases\test_preprocess.py || goto :fail

echo ============================================================
echo  4/5  Smoke training  (64 samples, 1 epoch; quick on CPU)
echo ============================================================
%PY% scripts\train.py --task detection --source cvefixes ^
    --model models\microsoft__codebert-base ^
    --epochs 1 --batch-size 8 --max-length 64 ^
    --max-train-samples 64 --max-eval-samples 32 ^
    --log-steps 4 --run-name quickstart || goto :fail

echo ============================================================
echo  5/5  Batch inference on the detection test cases
echo ============================================================
%PY% scripts\predict.py --checkpoint outputs\quickstart\best ^
    --input docs\test_cases\detection_test_cases.jsonl ^
    --output docs\test_cases\out_detection.jsonl --batch-size 4 || goto :fail

echo.
echo ============================================================
echo  ALL CHECKS PASSED
echo  Predictions -^> docs\test_cases\out_detection.jsonl
echo  NOTE: the smoke model is NOT trained, its accuracy is meaningless.
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [FAILED] See the message above.
pause
exit /b 1
