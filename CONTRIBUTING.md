# Contributing to REDRECON-X

Thank you for your interest in contributing to **REDRECON-X**! We welcome bug reports, feature enhancements, documentation improvements, and research benchmark datasets.

---

## Code of Conduct

By participating in this project, you agree to abide by the principles of respectful and constructive collaboration outlined in our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development Setup

1. **Fork & Clone**:
   ```bash
   git clone https://github.com/AnandBinuArjun/REDRECON-X.git
   cd REDRECON-X
   ```

2. **Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install pytest pytest-cov httpx
   pip install -e .
   ```

3. **Running the Test Suite**:
   ```bash
   python -m pytest tests/ -v --cov=redrecon
   ```

---

## Pull Request Guidelines

1. Create a descriptive branch: `git checkout -b feat/your-feature-name`.
2. Adhere to Python PEP 8 style standards and add type annotations where applicable.
3. Ensure all tests pass with 100% pass rate before submitting.
4. Add relevant unit or integration tests for any new reconnaissance module or analysis engine.
5. Submit your PR against the `main` branch with a clear description of the problem solved and test results.
