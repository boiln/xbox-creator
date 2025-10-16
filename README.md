## Automated Xbox Live account creation and XBL 3.0 token generation

## Features

-   Automated Microsoft account authentication
-   XSTS token generation for Xbox API access
-   Random gamertag generation using Xbox's AdjectiveNoun algorithm
-   Random gamerpic selection from Xbox's official library
-   Concurrent processing with configurable workers
-   Connection pooling and keep-alive optimization
-   Proxy support

## Fast requests-based token generation

https://github.com/user-attachments/assets/4313bcda-60f3-4439-8e11-bd9e0e41c492

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python xbl-token-gen.py
```

This will process accounts from `data/accounts.txt` with default settings.

### Command Line Arguments

| Argument             | Type   | Default             | Description                                                            |
| -------------------- | ------ | ------------------- | ---------------------------------------------------------------------- |
| `--accounts`         | path   | `data/accounts.txt` | Path to accounts file (format: email:password)                         |
| `--workers`          | int    | 8                   | Number of concurrent workers for parallel processing                   |
| `--debug`            | flag   | False               | Enable debug logging for detailed output                               |
| `--proxy`            | string | None                | HTTP proxy URL (e.g., `http://proxy:port`)                             |
| `--pool-size`        | int    | 100                 | HTTP connection pool size                                              |
| `--old-gamertag`     | flag   | False               | Use old random string method instead of Xbox's AdjectiveNoun algorithm |
| `--default-gamerpic` | flag   | False               | Use default gamerpic instead of random selection from Xbox             |
