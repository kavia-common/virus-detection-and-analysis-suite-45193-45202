#!/bin/bash
cd /home/kavia/workspace/code-generation/virus-detection-and-analysis-suite-45193-45202/virus_detector_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

