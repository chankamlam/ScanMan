@echo off
REM ============================================================
REM  One-click pipeline check for vuln_bert (CPU only, ~40s)
REM  Usage:  double-click, or run  docs\check_all.bat  from anywhere
REM  NOTE: keep this file ASCII-only so cmd does not garble it.
REM ============================================================
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

REM cd to project root (this file lives in <root>\docs\)
cd /d "%~dp0.."
set PYTHONPATH=%CD%

REM Pick an interpreter: conda py312 (has CUDA) -> CPU venv -> whatever is on PATH
set "PY=D:\Dev\Miniconda\envs\py312\python.exe"
if not exist "%PY%" set "PY=C:\Users\awu70\.workbuddy\binaries\python\envs\vuln_bert\Scripts\python.exe"
if not exist "%PY%" (
    echo [WARN] Neither known interpreter exists, falling back to "python" on PATH.
    echo        Edit the PY variable at the top of this file if that is wrong.
    set "PY=python"
)
echo Using interpreter: %PY%
echo.

echo ============================================================
echo  1/4  Environment check
echo ============================================================
%PY% scripts\check_env.py || goto :fail

echo ============================================================
echo  2/4  Preprocess unit tests (44 assertions)
echo ============================================================
%PY% docs\test_cases\test_preprocess.py || goto :fail

echo ============================================================
echo  3/4  Smoke training  (64 samples, 1 epoch; ~5s on GPU, ~15s on CPU)
echo ============================================================
%PY% scripts\train.py --task detection --source cvefixes ^
    --model models\microsoft__codebert-base ^
    --epochs 1 --batch-size 8 --max-length 64 ^
    --max-train-samples 64 --max-eval-samples 32 ^
    --log-steps 4 --run-name quickstart || goto :fail

echo ============================================================
echo  4/4  Batch inference on 20 detection test cases
echo ============================================================
%PY% scripts\predict.py --checkpoint outputs\quickstart\best ^
    --input docs\test_cases\detection_test_cases.jsonl ^
    --output docs\test_cases\out_detection.jsonl --batch-size 4 || goto :fail

echo.
echo ============================================================
echo  ALL CHECKS PASSED
echo  Predictions -^> docs\test_cases\out_detection.jsonl
echo  NOTE: the smoke model is NOT trained, accuracy ~0.4 is expected.
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [FAILED] See the message above.
pause
exit /b 1
