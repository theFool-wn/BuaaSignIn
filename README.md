# BuaaSignIn

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)  ![Made by Wang Nan](https://img.shields.io/badge/Made%20by-Wang%20Nan-brightgreen)  ![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange)  ![Python](https://img.shields.io/badge/Python-3.x-blue)

为了避免每次签到打卡都要排很长的队，所以制作该工具方便[签到](https://sign.wangnan.net)。

1. 填写BUAA统一认证（SSO）账号、密码，点击「查询课程」
2. 选择要签到的课程，点击「签到」
3. 为保证合理使用，本工具**仅查询当日课程**，在**课程开始前10分钟至课程结束期间**允许打卡
4. 由于服务器资源限制，本工具仅限内部人员使用
5. 为保证账号安全，本工具使用RSA非对称加密，同时服务器不保存密码
6. 部分账号由于弱密码或频繁异地登陆，可能无法查询课程
7. 本项目仅用于个人学习和研究交流，请勿用于违反学校规定的用途
8. 使用本工具造成的一切后果由使用者自行承担

## v2.0.0 大版本更新

1. 将原 `BuaaSignIn` 前端与 [`BuaaProxy`](https://github.com/theFool-wn/BuaaProxy) 的后端合并，统一使用 `Flask` 框架
2. 移除通用代理端口 `proxy()`
3. 迁移至 Cloudflare Python Worker 部署，提升稳定性与访问速度

## 主要路径

| 路径 | 说明 |
|---|---|
| `/` | 签到主页，输入账号密码查询课程并签到 |
| `/health` | 服务状态页，浏览器访问显示状态面板，API 请求返回 JSON |
| `/404` | 404 错误页 |
| `/robots.txt` | 爬虫协议 |
| `/sitemap.xml` | 网站地图 |
| `/api/config` | 获取公钥与服务状态 |
| `/api/iClassSchedule` | 课表查询接口（POST） |
| `/api/iClassSign` | 签到接口（POST） |

## 文件结构

```
BuaaSignIn/
├── BuaaSignIn_Worker.py    # Worker 主程序
├── wrangler.toml
├── pyproject.toml
├── README.md
├── LICENSE
├── public/
│   ├── index.html          # 签到主页
│   ├── health.html         # 健康状态页
│   ├── 404.html
│   ├── app.js              # 前端逻辑
│   ├── robots.txt
│   └── sitemap.xml
└── tools/                  # 辅助工具
    ├── generateRSAkey.py   # 生成 RSA 密钥对
    ├── generateSecrets.py  # 生成随机 Secret
    └── schema.sql          # 数据库结构定义脚本
```

## References:**

* [https://github.com/slvf/BUAA-iClassSignIn](https://github.com/slvf/BUAA-iClassSignIn)
* [https://github.com/fontlos/buaa-api](https://github.com/fontlos/buaa-api)

## License

This work is licensed under the **[CC BY-NC-SA 4.0 License](https://creativecommons.org/licenses/by-nc-sa/4.0/)**.

You are free to use, share, and adapt the code for **non-commercial purposes**, provided that:

* You must give **appropriate credit**, provide **a link to this License**, and indicate if modifications were made. You may give credit in any reasonable way, but you must not do so in any way that suggests that the licensor endorses you or your use.
* You **distribute any modifications under the same license**.

© 2025-2026 Wang Nan. All rights reserved.
