/*
  --- ВАЖНО: ФАЙЛ package.json ---
  Для работы на Railway создайте файл package.json рядом с этим файлом 
  и вставьте туда следующий код:

  {
    "name": "aura-shop",
    "version": "1.0.0",
    "main": "server.js",
    "scripts": {
      "start": "node server.js"
    },
    "dependencies": {
      "express": "^4.18.2",
      "cors": "^2.8.5",
      "body-parser": "^1.20.2",
      "rate-limiter-flexible": "^4.0.0",
      "node-fetch": "^3.3.2"
    },
    "engines": {
      "node": ">=18.0.0"
    }
  }
*/

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto'); 
const { RateLimiterMemory } = require('rate-limiter-flexible');
const path = require('path');

const app = express();

// ВАЖНО ДЛЯ RAILWAY: Разрешаем работу через прокси (Load Balancer)
app.set('trust proxy', 1);

// Railway автоматически выдает порт через process.env.PORT.
const PORT = process.env.PORT || 8080;

// --- КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ ---

// Хеши паролей (admin / password123 / Мопсики)
const ADMIN_HASHES = {
  login: '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
  password: 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f',
  secret: 'f0c059048a21f6625805541527757973c1772659160554743452033621415175'
};

const TG_CONFIG = {
  botToken: process.env.TG_BOT_TOKEN || '', 
  chatId: process.env.TG_CHAT_ID || ''
};

const rateLimiter = new RateLimiterMemory({
  points: 10,
  duration: 60 * 15, 
});

// Middleware
app.use(cors());
app.options('*', cors()); // Разрешаем Pre-flight запросы для всех маршрутов
app.use(bodyParser.json());

// Логирование запросов
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// Вспомогательные функции
const hash = (str) => crypto.createHash('sha256').update(str).digest('hex');
const safeCompare = (a, b) => {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

// --- API ROUTES (Определяем ДО статических файлов) ---

app.post('/api/auth/step1', async (req, res) => {
  const { login, password } = req.body;
  
  if (!req.body) {
    return res.status(400).json({ success: false, message: 'No body provided' });
  }

  try {
    await rateLimiter.consume(req.ip);
    const loginHash = hash(login || '');
    const passHash = hash(password || '');
    
    await new Promise(r => setTimeout(r, 500)); 

    const isLoginValid = safeCompare(loginHash, ADMIN_HASHES.login);
    const isPassValid = safeCompare(passHash, ADMIN_HASHES.password);

    if (isLoginValid && isPassValid) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false, message: 'Неверные данные' });
    }
  } catch (rejRes) {
    res.status(429).json({ success: false, message: 'Слишком много попыток.' });
  }
});

app.post('/api/auth/step2', async (req, res) => {
  const { secret } = req.body;

  try {
    await rateLimiter.consume(req.ip);
    const secretHash = hash(secret || '');
    
    await new Promise(r => setTimeout(r, 500));

    if (safeCompare(secretHash, ADMIN_HASHES.secret)) {
      res.json({ success: true, token: 'session-' + Date.now() });
    } else {
      res.status(401).json({ success: false, message: 'Неверный секретный код' });
    }
  } catch (rejRes) {
    res.status(429).json({ success: false, message: 'Блокировка доступа.' });
  }
});

app.post('/api/order', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  try {
    if (!TG_CONFIG.botToken) {
        console.error('Telegram Token не настроен!');
        return res.status(200).json({ success: true, warning: 'Telegram disabled' });
    }

    const fetch = (await import('node-fetch')).default;
    const tgUrl = `https://api.telegram.org/bot${TG_CONFIG.botToken}/sendMessage?chat_id=${TG_CONFIG.chatId}&text=${encodeURIComponent(message)}&parse_mode=Markdown`;
    
    const response = await fetch(tgUrl);
    const data = await response.json();

    if (data.ok) {
      res.json({ success: true });
    } else {
      console.error('TG Error:', data);
      res.status(500).json({ success: false, error: 'Telegram API Error' });
    }
  } catch (e) {
    console.error('Server Error:', e);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// Отлавливаем 404 для API, чтобы возвращать JSON, а не HTML
app.all('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'API route not found' });
});

// --- РАЗДАЧА ФРОНТЕНДА (После API, чтобы не перехватывать запросы) ---
app.use(express.static(path.join(__dirname, '.')));

// SPA Routing (для всех остальных запросов отдаем HTML)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});