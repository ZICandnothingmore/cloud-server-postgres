# Digital Key Server with PostgreSQL

Backend server cho hệ thống Digital Key, sử dụng Node.js, Express và PostgreSQL (Neon Cloud Database).

Project đã được cấu hình sẵn database và environment variables phục vụ mục đích test/demo.  
Chỉ cần clone project, cài dependencies và chạy server.

---

# Công nghệ sử dụng

- Node.js
- Express.js
- PostgreSQL
- Neon Database
- JWT Authentication
- Firebase Cloud Messaging (FCM)

---

# Yêu cầu trước khi chạy

Cần cài đặt:

- Node.js (khuyến nghị v16+)
- npm

Kiểm tra version:

```bash
node -v
npm -v
```

# Cài đặt Dependencies

```bash
npm install
```

---

# Chạy Server

Development mode:

```bash
npm run dev
```

Production mode:

```bash
npm start
```

Server mặc định chạy tại:

```text
http://localhost:3000
```
---

# Database

tạo file .env, copy file được gửi vào nhe

sử dụng postgre cloud: https://console.neon.tech/app/org-damp-sun-28077344/projects

# API Endpoints

## Authentication

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `GET /auth/me`
- `PATCH /auth/fcm-token`

## Vehicle

- `POST /vehicle/register`
- `GET /vehicle/my-modules`
- `GET /vehicle/:moduleId`

## Sharing

- `POST /sharing/check-legality`
- `POST /sharing/invite`
- `GET /sharing/pending`
- `POST /sharing/claim`
- `POST /sharing/report`

## Revocation

- `POST /revoke/friend`
- `GET /revoke/jobs`
- `POST /revoke/report`
- `POST /revoke/owner`

## Synchronization

- `POST /sync/upload`
- `GET /sync/list`

## Debug

- `GET /debug/events`
- `DELETE /debug/events`

---

# Debug Monitoring

Theo dõi API logs tại:

```text
http://localhost:3000/debug/events
```

---

# Cấu trúc thư mục

```text
cloud-server-postgres/
│
├── public/
├── src/
├── database/
├── .env
├── package.json
└── README.md
```

---

# License

ISC License