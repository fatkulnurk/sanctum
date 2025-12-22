# Laravel Sanctum Personal Access Tokens for Golang

[![Status](https://img.shields.io/badge/status-under%20development-orange)](https://github.com/fatkulnurk/sanctum)

## 🚧 Under Development

This project is **actively under development**. Core functionality is incomplete, APIs are unstable, and **it is not suitable for production use**.

## Introduction

Laravel Sanctum-compatible personal access tokens for Golang. Generate and validate tokens in the exact same format (`id|plain-token`), use the same database schema, and share tokens seamlessly between Laravel and Go services.

This library enables Go applications to:
- Issue tokens compatible with Laravel Sanctum's storage and validation
- Verify tokens issued by Laravel Sanctum
- Share authentication state across mixed Laravel/Golang