require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const TelegramBot = require('node-telegram-bot-api');
const app = express();
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

const allowedOrigins = process.env.CLIENT_ORIGIN
    ? process.env.CLIENT_ORIGIN.split(',')
    : ['http://localhost:5173'];
app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

app.use(bodyParser.json());
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });

app.get('/api/validate-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) return res.status(401).send();

    try {
        jwt.verify(token, 'your_secret_key');
        res.status(200).send();
    } catch {
        res.status(401).send();
    }
});
bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const options = {
        reply_markup: {
            keyboard: [
                [{ text: "Добавить новую бронь" }],
                [{ text: "Посмотреть бронирования" }]
            ],
            resize_keyboard: true,
            one_time_keyboard: true
        }
    };
    bot.sendMessage(chatId, "Добро пожаловать! Выберите действие:", options);
});

async function sendVerificationCall(phone_number) {
    const response = await fetch(`https://sms.ru/code/call?phone=${phone_number}&ip=33.22.11.55&api_id=CC44BACB-0E72-2AE0-02C3-EA2D9679718E`, {
        method: 'GET',
    });
    return await response.json();
}

app.post('/register', async (req, res) => {
    const { phone_number } = req.body;

    const existingUser = await pool.query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);
    if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Этот номер телефона уже зарегистрирован' });
    }

    const callResponse = await sendVerificationCall(phone_number);
    console.log(callResponse)
    if (callResponse.status !== "OK") {
        return res.status(500).json({ error: 'Не удалось отправить звонок для верификации.' });
    }

    const verificationCode = callResponse.code;
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
        'INSERT INTO verification_codes (phone_number, code, expires_at) VALUES ($1, $2, $3)',
        [phone_number, verificationCode, expiresAt]
    );

    res.status(200).json({ message: 'Код верификации отправлен на Ваш номер телефона.' });
});

app.post('/verify-registration', async (req, res) => {
    const { first_name, last_name, password, phone_number, verification_code } = req.body;

    const result = await pool.query(
        'SELECT * FROM verification_codes WHERE phone_number = $1 AND code = $2 AND expires_at > NOW()',
        [phone_number, verification_code]
    );

    if (result.rows.length === 0) {
        await pool.query(
            'DELETE FROM verification_codes WHERE phone_number = $1',
            [phone_number]
        );
        return res.status(400).json({ error: 'Неверный или истекший код верификации.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const adminCheck = await pool.query(
            'SELECT * FROM admins WHERE phone_number = $1',
            [phone_number]
        );

        const role = adminCheck.rows.length > 0 ? 'admin' : 'user';

        const insertResult = await pool.query(
            'INSERT INTO users (first_name, last_name, password, phone_number, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [first_name, last_name, hashedPassword, phone_number, role]
        );

        const userId = insertResult.rows[0].id;
        const token = jwt.sign({ first_name, last_name, phone_number, userId, role }, 'secret_key', { expiresIn: '7d' });

        await pool.query(
            'DELETE FROM verification_codes WHERE phone_number = $1',
            [phone_number]
        );

        res.status(201).json({ message: 'Пользователь создан', token, userId, first_name, last_name });
    } catch (err) {
        console.error("Ошибка регистрации:", err);
        await pool.query(
            'DELETE FROM verification_codes WHERE phone_number = $1',
            [phone_number]
        );
        res.status(500).json({ error: 'Ошибки сервера' });
    }
});


app.post('/login', async (req, res) => {
    const { phone_number, password } = req.body;

    if (!phone_number || !password) {
        return res.status(400).json({ message: 'Введите номер телефона и пароль' });
    }

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Пользователя с таким номером телефона не существует!' });
        }

        const user = userResult.rows[0];
        const role = user.role || 'user';

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: 'Неверный пароль! Попробуйте снова.' });
        }

        const token = jwt.sign({ userId: user.id, role }, 'secret_key', { expiresIn: '7d' });

        return res.json({
            token,
            userId: user.id,
            first_name: user.first_name,
            last_name: user.last_name
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        return res.status(500).json({ message: 'Ошибка сервера. Попробуйте позже.' });
    }
});

app.post("/forgot-password", async (req, res) => {
    const { phone_number } = req.body;

    try {
        const user = await pool.query("SELECT * FROM users WHERE phone_number = $1", [phone_number]);
        if (user.rows.length === 0) {
            return res.status(400).json({ error: "Номер телефона не зарегистрирован" });
        }

        const callResponse = await sendVerificationCall(phone_number);
        if (callResponse.status !== "OK") {
            return res.status(500).json({ error: "Ошибка отправки кода" });
        }

        const verificationCode = callResponse.code;
        await pool.query("INSERT INTO verification_codes (phone_number, code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes') ON CONFLICT (phone_number) DO UPDATE SET code = $2, expires_at = NOW() + INTERVAL '10 minutes'", [phone_number, verificationCode]);

        res.json({ message: "Код отправлен на ваш номер телефона" });
    } catch (error) {
        console.error("Ошибка восстановления пароля:", error);
        res.status(500).json({ error: "Ошибка сервера" });
    }
});
app.post("/verify-code", async (req, res) => {
    const { phone_number, verification_code } = req.body;

    try {
        const result = await pool.query(
            "SELECT * FROM verification_codes WHERE phone_number = $1 ORDER BY created_at DESC LIMIT 1",
            [phone_number]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Для этого номера телефона код не был отправлен." });
        }

        const verificationRecord = result.rows[0];
        const storedCode = verificationRecord.code;
        const expiresAt = verificationRecord.expires_at;

        if (new Date() > new Date(expiresAt)) {
            return res.status(400).json({ error: "Срок действия кода истёк. Пожалуйста, запросите новый код." });
        }

        if (verification_code !== storedCode) {
            return res.status(401).json({ error: "Неверный код." });
        }

        await pool.query("DELETE FROM verification_codes WHERE phone_number = $1", [phone_number]);

        res.json({ message: "Код подтверждения верен!" });
    } catch (error) {
        console.error("Ошибка верификации кода:", error);
        res.status(500).json({ error: "Ошибка сервера при верификации кода." });
    }
});
app.post("/reset-password", async (req, res) => {
    const { phone_number, verification_code, new_password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM verification_codes WHERE phone_number = $1 AND code = $2", [phone_number, verification_code]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Неверный код или срок его действия истёк." });
        }

        await pool.query("UPDATE users SET password = $1 WHERE phone_number = $2", [new_password, phone_number]);

        res.json({ message: "Пароль успешно обновлён." });
    } catch (error) {
        console.error("Ошибка восстановления пароля:", error);
        res.status(500).json({ error: "Ошибка сервера при восстановлении пароля." });
    }
});

function authenticateToken(req, res, next) {
    const openPaths = [
        '/login',
        '/register',
        '/verify-registration',
        '/forgot-password',
        '/verify-code',
        '/api/login',
        '/api/register',
    ];

    if (openPaths.includes(req.path)) {
        return next();
    }

    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}

app.use(authenticateToken);

app.get('/userAccount/:userId/profileData', async (req, res) => {
    const { userId } = req.params;
    try {
        const result = await pool.query('SELECT first_name, last_name, phone_number FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const userProfile = result.rows[0];
        res.status(200).json(userProfile);
    } catch (err) {
        console.error("Ошибка получения профиля:", err);
        res.status(500).json({ error: 'Ошибки сервера' });
    }
});
app.post('/request-phone-change', async (req, res) => {
    const { userId, new_phone_number } = req.body;

    const existingUser = await pool.query('SELECT * FROM users WHERE phone_number = $1', [new_phone_number]);
    if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Этот номер уже используется другим пользователем' });
    }

    const callResponse = await sendVerificationCall(new_phone_number);
    if (callResponse.status !== "OK") {
        return res.status(500).json({ error: 'Ошибка отправки кода' });
    }

    const verificationCode = callResponse.code;
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
        'INSERT INTO verification_codes (user_id, phone_number, code, expires_at) VALUES ($1, $2, $3, $4)',
        [userId, new_phone_number, verificationCode, expiresAt]
    );

    res.status(200).json({ message: 'Код отправлен' });
});
app.post('/verify-phone-change', async (req, res) => {
    const { userId, new_phone_number, verification_code } = req.body;

    const result = await pool.query(
        'SELECT * FROM verification_codes WHERE user_id = $1 AND phone_number = $2 AND code = $3 AND expires_at > NOW()',
        [userId, new_phone_number, verification_code]
    );

    if (result.rows.length === 0) {
        return res.status(400).json({ error: 'Неверный или истекший код' });
    }

    await pool.query('UPDATE users SET phone_number = $1 WHERE id = $2', [new_phone_number, userId]);
    await pool.query('DELETE FROM verification_codes WHERE user_id = $1 AND phone_number = $2', [userId, new_phone_number]);

    res.status(200).json({ message: 'Номер успешно обновлён' });
});
app.post('/userAccount/:userId/editProfile', async (req, res) => {
    const { userId, first_name, last_name, phone_number, current_password, new_password } = req.body;

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (existingUser.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        const phoneCheck = await pool.query('SELECT * FROM users WHERE phone_number = $1 AND id != $2', [phone_number, userId]);
        if (phoneCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Этот номер телефона уже зарегистрирован' });
        }

        const nameRegex = /^[А-Яа-яЁёs]+$/;
        if (!nameRegex.test(first_name) || !nameRegex.test(last_name)) {
            return res.status(400).json({ error: 'Имя и фамилия должны содержать только русские буквы.' });
        }

        const phoneRegex = /^((8|\+7)[\- ]?)?(\(?\d{3}\)?[\- ]?)?[\d\- ]{9,12}$/;
        if (!phoneRegex.test(phone_number)) {
            return res.status(400).json({ error: 'Введите номер телефона корректно.' });
        }

        if (current_password && new_password) {
            const user = existingUser.rows[0];
            const isMatch = await bcrypt.compare(current_password, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: 'Неверный текущий пароль' });
            }
        }

        let updates = [];
        let values = [];

        if (first_name) {
            updates.push(`first_name = $${updates.length + 1}`);
            values.push(first_name);
        }
        if (last_name) {
            updates.push(`last_name = $${updates.length + 1}`);
            values.push(last_name);
        }
        if (phone_number) {
            updates.push(`phone_number = $${updates.length + 1}`);
            values.push(phone_number);
        }
        if (new_password) {
            const hashedPassword = await bcrypt.hash(new_password, 10);
            updates.push(`password = $${updates.length + 1}`);
            values.push(hashedPassword);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'Нет изменений для обновления' });
        }

        await pool.query(
            `UPDATE users SET ${updates.join(', ')} WHERE id = $${updates.length + 1}`,
            [...values, userId]
        );

        res.status(200).json({ message: 'Профиль успешно обновлён' });

    } catch (err) {
        console.error("Ошибка обновления профиля:", err);
        res.status(500).json({ error: 'Внутренняя ошибка сервера. Попробуйте снова.' });
    }
});

app.get('/userAccount/:userId/availableIntervals/:booking_date_start', async (req, res) => {
    const { booking_date_start } = req.params;

    try {
        const intervalsResult = await pool.query(
            'SELECT id, start_time, end_time FROM booking_intervals WHERE booking_date = $1',
            [booking_date_start]
        );

        const bookingsResult = await pool.query(
            'SELECT start_time, end_time FROM bookings WHERE booking_date = $1 ORDER BY start_time',
            [booking_date_start]
        );

        const intervals = intervalsResult.rows;
        const bookings = bookingsResult.rows;
        let availableStartTimes = [];

        const now = new Date();
        const minPreparationTime = 2 * 60 * 60 * 1000; // 2 hours in ms

        intervals.forEach(interval => {
            // Parse interval times (format: "08:00")
            const intervalStart = new Date(`${booking_date_start}T${interval.start_time.padStart(5, '0')}:00`);
            const intervalEnd = new Date(`${booking_date_start}T${interval.end_time.padStart(5, '0')}:00`);

            // Adjust interval start if it's in the past
            if (intervalStart <= now) {
                const adjustedStartTime = new Date(now.getTime() + minPreparationTime);
                adjustedStartTime.setMinutes(0, 0, 0); // Round to full hour

                if (adjustedStartTime >= intervalEnd) {
                    return; // Skip this interval if adjusted start is after end
                }
                intervalStart.setTime(adjustedStartTime.getTime());
            }

            // Generate all possible 2-hour slots within the interval
            for (let time = new Date(intervalStart); time < intervalEnd; time.setHours(time.getHours() + 1)) {
                const potentialStart = new Date(time);
                const potentialEnd = new Date(potentialStart);
                potentialEnd.setHours(potentialEnd.getHours() + 2);

                if (potentialEnd > intervalEnd) {
                    continue; // Skip if the 2-hour slot doesn't fit
                }

                // Check against existing bookings
                let isAvailable = true;

                for (const booking of bookings) {
                    // Parse booking times (format: "2025-03-30T17:00:00.000Z")
                    const bookingStart = new Date(booking.start_time);
                    const bookingEnd = new Date(booking.end_time);

                    // Check for direct overlap
                    if (potentialStart < bookingEnd && potentialEnd > bookingStart) {
                        isAvailable = false;
                        break;
                    }

                    // Check 1-hour gap before potential booking
                    const oneHourBeforePotential = new Date(potentialStart);
                    oneHourBeforePotential.setHours(oneHourBeforePotential.getHours() - 1);
                    if (oneHourBeforePotential < bookingEnd && potentialStart > bookingStart) {
                        isAvailable = false;
                        break;
                    }

                    // Check 1-hour gap after potential booking
                    const oneHourAfterPotential = new Date(potentialEnd);
                    oneHourAfterPotential.setHours(oneHourAfterPotential.getHours() + 1);
                    if (oneHourAfterPotential > bookingStart && potentialEnd < bookingEnd) {
                        isAvailable = false;
                        break;
                    }
                }

                if (isAvailable) {
                    availableStartTimes.push({
                        startTime: potentialStart.toTimeString().slice(0, 5),
                        intervalId: interval.id
                    });
                }
            }
        });

        // Remove duplicates and sort
        const distinctStartTimes = [...new Map(availableStartTimes.map(item => [item.startTime, item])).values()]
            .sort((a, b) => a.startTime.localeCompare(b.startTime));

        res.status(200).json({ availableStartTimes: distinctStartTimes });

    } catch (error) {
        console.error("Ошибка при получении доступных интервалов:", error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/userAccount/:userId/availableEndTimes/:booking_date/:start_time/:intervalId', async (req, res) => {
    const { booking_date, start_time, intervalId } = req.params;

    try {
        const intervalResult = await pool.query(
            'SELECT start_time, end_time FROM booking_intervals WHERE booking_date = $1 AND id = $2',
            [booking_date, intervalId]
        );

        const bookingsResult = await pool.query(
            'SELECT start_time, end_time FROM bookings WHERE booking_date = $1 ORDER BY start_time',
            [booking_date]
        );

        const interval = intervalResult.rows[0];
        const bookings = bookingsResult.rows;

        if (!interval) {
            return res.status(404).json({ error: 'Interval not found' });
        }

        // Обработка времени окончания интервала (24:00 -> 23:59:59)
        const intervalEndTime = interval.end_time === '24:00' ? '23:59:59' : interval.end_time;

        const intervalStart = new Date(`${booking_date}T${interval.start_time}`);
        const intervalEnd = new Date(`${booking_date}T${intervalEndTime}`);
        const selectedStartTime = new Date(`${booking_date}T${start_time}`);

        let availableEndTimes = [];

        if (selectedStartTime >= intervalStart && selectedStartTime < intervalEnd) {
            // Минимальное время окончания (ровно 2 часа от начала)
            const minEndTime = new Date(selectedStartTime);
            minEndTime.setHours(minEndTime.getHours() + 2);

            // Максимальное время окончания (конец интервала)
            const maxEndTime = new Date(intervalEnd);

            // Если интервал заканчивается в 24:00, добавляем это время как вариант
            if (interval.end_time === '24:00') {
                maxEndTime.setHours(24, 0, 0, 0);
            }

            // Проверяем все возможные варианты окончания
            for (let endTime = new Date(minEndTime); endTime <= maxEndTime; endTime.setHours(endTime.getHours() + 1)) {
                // Для случая 24:00
                if (endTime.getHours() === 24) {
                    endTime.setHours(23, 59, 59);
                }

                let isAvailable = true;

                // Проверяем каждое существующее бронирование
                for (const booking of bookings) {
                    const bookingStart = new Date(booking.start_time);
                    const bookingEnd = new Date(booking.end_time);

                    // Проверка пересечения
                    if (selectedStartTime < bookingEnd && endTime > bookingStart) {
                        isAvailable = false;
                        break;
                    }
                }

                if (isAvailable) {
                    // Форматируем 23:59:59 как 24:00 для отображения
                    const displayTime = endTime.getHours() === 23 && endTime.getMinutes() === 59 ? '24:00' :
                        endTime.toTimeString().slice(0, 5);

                    availableEndTimes.push({
                        endTime: displayTime
                    });
                }
            }
        }

        res.json({ availableEndTimes });
    } catch (error) {
        console.error('Ошибка при получении доступных конечных времен:', error);
        res.status(500).json({ error: 'Произошла ошибка при получении доступных конечных времен.' });
    }
});
app.get('/userAccount/:userId/bookings', async (req, res) => {
    console.log('Запрос получен!');
    try {
        const { userId } = req.params;

        const result = await pool.query(
            `SELECT 
                b.id AS booking_id,
                b.booking_date,
                b.start_time,
                b.end_time,
                b.broom,
                b.broom_quantity, 
                b.towel,
                b.towel_quantity,
                b.hat,
                b.hat_quantity,
                b.sheets,
                b.sheets_quantity,
                b.price,
                CASE 
                    WHEN d.id IS NOT NULL THEN 'Действует акция'
                    ELSE 'Нет акции'
                END AS discount_status
            FROM 
                bookings b
            LEFT JOIN 
                discounts d ON b.discount_id = d.id
            WHERE 
                b.user_id = $1`, [userId]
        );

        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Ошибка при получении бронирований:', error);
        res.status(500).json({ error: 'Ошибка при получении бронирований' });
    }
});
app.post('/userAccount/:userId/book', async (req, res) => {
    try {
        const { userId } = req.params;
        const { booking_date, start_time, end_time, price, broom, broom_quantity, towel, towel_quantity, hat, hat_quantity, sheets, sheets_quantity, discount_id } = req.body;
        if (!userId || !booking_date || !start_time || !end_time) {
            return res.status(400).json({ message: "Отсутствуют обязательные поля: userId, booking_date, start_time, end_time." });
        }

        const startTime = new Date(`${booking_date}T${start_time}`);
        const endTime = midnightCheck(booking_date, end_time);
        const existingBookings = await pool.query(
            `SELECT *
                FROM bookings b
                WHERE booking_date = $1
                AND EXISTS (
                    SELECT 1
                    FROM bookings b2
                    WHERE b2.booking_date = $1
                    AND (
                        (b2.start_time BETWEEN $2 AND $3) OR  
                        (b2.end_time BETWEEN $2 AND $3)   OR  
                        ($2 BETWEEN b2.start_time AND b2.end_time) OR 
                        ($3 BETWEEN b2.start_time AND b2.end_time)     
                    )
                    
                );`,
            [booking_date, startTime, endTime]
        );

        if (existingBookings.rows.length > 0) {
            return res.status(400).json({ message: 'Этот временной интервал уже забронирован.' });
        }

        const result = await pool.query(
            'INSERT INTO bookings (user_id, booking_date, start_time, end_time, price, broom, broom_quantity, towel, towel_quantity, hat, hat_quantity, sheets, sheets_quantity, discount_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING *',
            [userId, booking_date, startTime, endTime, price, broom, broom_quantity, towel, towel_quantity, hat, hat_quantity, sheets, sheets_quantity, discount_id]
        );

        const userResult = await pool.query('SELECT first_name, last_name, phone_number FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        const adminsResult = await pool.query('SELECT * FROM admins');
        const admins = adminsResult.rows;

        const message = `Новое бронирование:\nПользователь: ${user.first_name} ${user.last_name}\nТелефон: ${user.phone_number}\nДата: ${new Date(booking_date).toLocaleDateString('ru-RU')}\nВремя: ${start_time} - ${end_time}\nЦена: ${price}\nМетлы: ${broom_quantity}\nПолотенца: ${towel_quantity}\nШапки: ${hat_quantity}\nПростыни: ${sheets_quantity}`;
        bot.on('message', (msg) => {
            const chatId = msg.chat.id;
            console.log(`Chat ID: ${chatId}`);
        });
        admins.forEach(admin => {
            bot.sendMessage(admin.chat_id, message)
                .catch(err => {
                    console.error(`Ошибка при отправке сообщения администратору ${admin.chat_id}:`, err);
                });
        });

        const bookingId = result.rows[0].id;
        res.status(200).json({ message: 'Бронирование успешно', id: bookingId });
    } catch (error) {
        console.error('Ошибка при бронировании:', error);
        res.status(500).json({ error: 'Ошибка при бронировании' });
    }
});
app.delete('/userAccount/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.status(200).json({ message: 'Аккаунт успешно удален' });
    } catch (error) {
        console.error('Ошибка при удалении аккаунта:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
let waitingForInput = false;

bot.onText(/\/add_booking/, async (msg) => {
    waitingForInput = false;
    const chatId = msg.chat.id;
    const availableDates = await getAvailableBookingDates();

    if (availableDates.length === 0) {
        bot.sendMessage(chatId, "Нет доступных дат для бронирования.");
        return;
    }

    const dateButtons = availableDates.map(date => [{ text: date, callback_data: date }]);

    bot.sendMessage(chatId, "Выберите доступную дату для бронирования:", {
        reply_markup: { inline_keyboard: dateButtons }
    });
});

bot.on('callback_query', async (callbackQuery) => {
    if (waitingForInput) return;
    waitingForInput = true;

    const chatId = callbackQuery.message.chat.id;
    const selectedDate = callbackQuery.data;
    const formattedDate = selectedDate.split('.').reverse().join('-');
    const availableStartTimes = await getAvailableTimes(formattedDate);

    if (availableStartTimes.length === 0) {
        bot.sendMessage(chatId, "Нет доступных временных интервалов для выбранной даты.");
        waitingForInput = false;
        return;
    }

    const timeButtons = generateTimeButtons(availableStartTimes, formattedDate);

    bot.sendMessage(chatId, "Выберите время начала бронирования:", {
        reply_markup: { inline_keyboard: timeButtons }
    });

    bot.once('callback_query', async (timeCallback) => {
        const startTime = new Date(`${formattedDate}T${timeCallback.data}`);
        const availableEndTimes = await getAvailableEndTimes(formattedDate, startTime);

        if (availableEndTimes.length === 0) {
            bot.sendMessage(chatId, "Нет доступных временных интервалов для окончания бронирования.");
            waitingForInput = false;
            return;
        }

        const endTimeButtons = generateEndTimeButtons(startTime, availableEndTimes);

        bot.sendMessage(chatId, "Выберите время окончания бронирования:", {
            reply_markup: { inline_keyboard: endTimeButtons }
        });

        bot.once('callback_query', async (endTimeCallback) => {
            const endTime = midnightCheck(formattedDate, endTimeCallback.data);
            const bookingData = { chatId, formattedDate, startTime, endTime };
            await collectUserData(bookingData);
        });
    });
});

async function collectUserData(bookingData) {
    const { chatId, formattedDate, startTime, endTime } = bookingData;

    const first_name = await askUser(chatId, "Введите имя пользователя:");
    const last_name = await askUser(chatId, "Введите фамилию пользователя:");
    const phone_number = await askUser(chatId, "Введите номер телефона пользователя:");
    const broom_quantity = parseInt(await askUser(chatId, "Введите количество веников (0, если не нужно):")) || 0;
    const towel_quantity = parseInt(await askUser(chatId, "Введите количество полотенец (0, если не нужно):")) || 0;
    const hat_quantity = parseInt(await askUser(chatId, "Введите количество шапок (0, если не нужно):")) || 0;
    const sheets_quantity = parseInt(await askUser(chatId, "Введите количество простыней (0, если не нужно):")) || 0;

    const isWeekend = [0, 6].includes(startTime.getDay());
    const price = calculatePrice(startTime, endTime, isWeekend, broom_quantity, towel_quantity, hat_quantity, sheets_quantity);

    bot.sendMessage(chatId, `Итоговая стоимость: ${price}₽`);

    const guestResult = await pool.query(
        'INSERT INTO guest_users (first_name, last_name, phone_number) VALUES ($1, $2, $3) RETURNING id',
        [first_name, last_name, phone_number]
    );

    const guestId = guestResult.rows[0].id;

    const bookingResult = await pool.query(
        `INSERT INTO bookings 
        (user_id, booking_date, start_time, end_time, price, broom, broom_quantity, towel, towel_quantity, hat, hat_quantity, sheets, sheets_quantity) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
        [guestId, formattedDate, startTime, endTime, price, broom_quantity > 0, broom_quantity, towel_quantity > 0, towel_quantity, hat_quantity > 0, hat_quantity, sheets_quantity > 0, sheets_quantity]
    );

    const bookingId = bookingResult.rows[0].id;

    let servicesMessage = '';
    if (broom_quantity > 0) servicesMessage += `🌿 Веники: ${broom_quantity} шт.\n`;
    if (towel_quantity > 0) servicesMessage += `🛁 Полотенца: ${towel_quantity} шт.\n`;
    if (hat_quantity > 0) servicesMessage += `🎩 Шапки: ${hat_quantity} шт.\n`;
    if (sheets_quantity > 0) servicesMessage += `🛏 Простыни: ${sheets_quantity} шт.\n`;

    bot.sendMessage(chatId, `✅ *Бронирование успешно создано!*  
📅 *Дата*: ${formattedDate}  
⏰ *Время*: ${startTime.toTimeString().slice(0, 5)} - ${endTime.toTimeString().slice(0, 5)}  
👤 *Клиент*: ${first_name} ${last_name}  
📞 *Телефон*: ${phone_number}  
${servicesMessage ? `🛠 *Доп. услуги:*\n${servicesMessage}` : ''}  
💰 *Цена*: ${price}₽  
🆔 *ID бронирования*: ${bookingId}`, { parse_mode: 'Markdown' });

    waitingForInput = false;
}
async function askUser(chatId, question) {
    return new Promise((resolve) => {
        bot.sendMessage(chatId, question);
        bot.once('message', (msg) => resolve(msg.text));
    });
}
function generateTimeButtons(availableStartTimes, formattedDate) {
    const timeButtons = [];
    const uniqueTimes = new Set();

    for (const interval of availableStartTimes) {
        const intervalStart = new Date(`${formattedDate}T${interval.start}`);
        const intervalEnd = midnightCheck(formattedDate, interval.end);
        let time = new Date(intervalStart);
        while (time <= intervalEnd) {
            const timeString = time.toTimeString().slice(0, 5);
            if (!uniqueTimes.has(timeString)) {
                uniqueTimes.add(timeString);
                timeButtons.push([{ text: timeString, callback_data: timeString }]);
            }
            time.setHours(time.getHours() + 1);
        }
    }
    return timeButtons;
}
function generateEndTimeButtons(startTime, availableEndTimes) {
    const endTimeButtons = [];
    const uniqueEndTimes = new Set();

    for (const interval of availableEndTimes) {
        let intervalEnd = midnightCheck(startTime.toISOString().split('T')[0], interval.end);
        let validEndTimeStart = new Date(startTime);
        validEndTimeStart.setHours(validEndTimeStart.getHours() + 2);

        while (validEndTimeStart <= intervalEnd) {
            const timeString = validEndTimeStart.toTimeString().slice(0, 5);
            if (!uniqueEndTimes.has(timeString)) {
                uniqueEndTimes.add(timeString);
                endTimeButtons.push([{ text: timeString, callback_data: timeString }]);
            }
            validEndTimeStart.setHours(validEndTimeStart.getHours() + 1);
        }
    }
    return endTimeButtons;
}
async function getAvailableBookingDates() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    try {
        const result = await pool.query(
            'SELECT DISTINCT booking_date FROM booking_intervals WHERE booking_date > $1 ORDER BY booking_date ASC',
            [today.toISOString().split('T')[0]]
        );

        const availableDates = [];

        for (const row of result.rows) {
            const date = new Date(row.booking_date);
            const formattedDate = `${String(date.getDate()).padStart(2, '0')}.${String(date.getMonth() + 1).padStart(2, '0')}.${date.getFullYear()}`;

            const availableTimes = await getAvailableTimes(row.booking_date);
            if (availableTimes.length > 0) {
                availableDates.push(formattedDate);
            }
        }

        return availableDates;
    } catch (error) {
        console.error('Ошибка при получении доступных дат:', error);
        return [];
    }
}
async function getAvailableTimes(booking_date) {
    const intervalsResult = await pool.query(
        'SELECT id, start_time, end_time FROM booking_intervals WHERE booking_date = $1',
        [booking_date]
    );
    const bookedTimes = await pool.query(
        'SELECT start_time, end_time FROM bookings WHERE booking_date = $1',
        [booking_date]
    );
    const bookedIntervals = bookedTimes.rows.map(booking => ({
        start: new Date(booking.start_time),
        end: new Date(booking.end_time),
    }));
    const availableStartTimes = [];

    intervalsResult.rows.forEach(interval => {
        const intervalStart = new Date(`${booking_date}T${interval.start_time}`);
        let intervalEnd = new Date(`${booking_date}T${interval.end_time}`);


        for (let time = new Date(intervalStart); time <= intervalEnd; time.setHours(time.getHours() + 1)) {
            const potentialStartTime = new Date(time);
            const potentialEndTime = new Date(potentialStartTime);
            potentialEndTime.setHours(potentialEndTime.getHours() + 2);
            if (potentialEndTime <= intervalEnd) {
                const isBooked = bookedIntervals.some(booking => {
                    const bookingStart = new Date(booking.start);
                    const bookingEnd = new Date(booking.end);
                    return (
                        (potentialStartTime < bookingEnd && potentialEndTime > new Date(bookingStart.getTime() - 3600000)) ||
                        (potentialStartTime >= bookingStart && potentialStartTime <= bookingEnd)
                    );
                });

                if (!isBooked) {
                    availableStartTimes.push({
                        start: potentialStartTime.toTimeString().slice(0, 5),
                        end: potentialEndTime.toTimeString().slice(0, 5)
                    });
                }
            }
        }
    });

    return availableStartTimes;
}
async function getAvailableEndTimes(booking_date, startTime) {
    const intervalsResult = await pool.query(
        'SELECT start_time, end_time FROM booking_intervals WHERE booking_date = $1 AND end_time > $2',
        [booking_date, startTime.toTimeString().slice(0, 5)]
    );

    const bookingsResult = await pool.query(
        'SELECT start_time, end_time FROM bookings WHERE booking_date = $1',
        [booking_date]
    );

    const bookings = bookingsResult.rows.map(booking => ({
        start: new Date(booking.start_time),
        end: new Date(booking.end_time),
    }));

    const availableEndTimes = [];
    const potentialStartTime = new Date(`${booking_date}T${startTime.toTimeString().slice(0, 5)}`);
    const minEndTime = new Date(potentialStartTime);
    minEndTime.setHours(minEndTime.getHours() + 2);

    for (const interval of intervalsResult.rows) {
        const intervalStart = new Date(`${booking_date}T${interval.start_time}`);
        const intervalEnd = new Date(`${booking_date}T${interval.end_time}`);

        if (potentialStartTime >= intervalStart && potentialStartTime <= intervalEnd) {
            for (let time = minEndTime; time <= intervalEnd; time.setHours(time.getHours() + 1)) {
                const potentialEndTime = new Date(time);

                const isBooked = bookings.some(booking => {
                    const bookingStart = new Date(booking.start);
                    const bookingEnd = new Date(booking.end);
                    return (potentialEndTime > bookingStart && potentialStartTime < bookingEnd) || (potentialEndTime >= bookingStart && potentialEndTime <= new Date(bookingEnd.getTime() + 3600000));
                });

                if (!isBooked) {
                    availableEndTimes.push({ end: potentialEndTime.toTimeString().slice(0, 5) });
                    console.log(availableEndTimes)
                }
            }
        }
    }
    return availableEndTimes;
}
const midnightCheck = (date, endTime) => {
    if (endTime === '00:00') {
        const nextDay = new Date(date);
        nextDay.setDate(nextDay.getDate() + 1);
        return new Date(`${nextDay.toISOString().split('T')[0]}T${endTime}`);
    }
    return new Date(`${date}T${endTime}`);
}
const calculatePrice = (start, end, isWeekend, broom_quantity, towel_quantity, hat_quantity, sheets_quantity) => {
    if (end.getHours() === 0 && end.getMinutes() === 0) {
        end.setHours(23, 59, 59);
    }

    if (end <= start) {
        return 0;
    }

    const hours = (end.getTime() - start.getTime()) / (1000 * 60 * 60);
    let cost = 0;

    const startHour = start.getHours();
    const dayOfWeek = start.getDay();

    if (dayOfWeek === 0 || dayOfWeek === 6) {
        cost = hours <= 2 ? 3800 : 1600 * hours;
    } else {
        if (startHour >= 8 && startHour < 16) {
            cost = hours <= 2 ? 3500 : 1500 * hours;
        } else if (startHour >= 17 && startHour < 24) {
            cost = hours <= 2 ? 3800 : 1600 * hours;
        }
    }
    cost += (broom_quantity * 500) + (towel_quantity * 200) + (hat_quantity * 300) + (sheets_quantity * 400);
    return cost;
};
app.get('/userAccount/:userId/discounts', async (req, res) => {
    const { userId } = req.params;

    try {
        const result = await pool.query('SELECT * FROM discounts');

        res.status(200).json(result.rows);
    } catch (error) {
        console.error("Ошибка при получении скидок:", error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.delete('/userAccount/:userId/bookings/:bookingId', async (req, res) => {
    const { userId, bookingId } = req.params;

    console.log('userId:', userId);
    console.log('bookingId:', bookingId);

    if (!bookingId || !userId) {
        return res.status(400).json({ message: 'Неверные параметры.' });
    }

    try {
        const booking = await pool.query('SELECT * FROM bookings WHERE id = $1 AND user_id = $2', [bookingId, userId]);
        if (booking.rows.length === 0) {
            return res.status(404).json({ message: 'Бронь не найдена.' });
        }

        const userResult = await pool.query('SELECT first_name, last_name, phone_number FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        const adminsResult = await pool.query('SELECT * FROM admins');
        const admins = adminsResult.rows;

        await pool.query('DELETE FROM bookings WHERE id = $1', [bookingId]);

        const startTime = new Date(booking.rows[0].start_time);
        const endTime = new Date(booking.rows[0].end_time);
        const formattedStartTime = startTime.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        const formattedEndTime = endTime.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        const message = `Бронь отменена:\nПользователь: ${user.first_name} ${user.last_name}\nТелефон: ${user.phone_number}\nДата: ${new Date(booking.rows[0].booking_date).toLocaleDateString('ru-RU')}\nВремя: ${formattedStartTime} - ${formattedEndTime}\nЦена: ${booking.rows[0].price}`;
        admins.forEach(admin => {
            bot.sendMessage(admin.chat_id, message)
                .catch(err => {
                    console.error(`Ошибка при отправке сообщения администратору ${admin.chat_id}:`, err);
                });
        });

        res.status(200).json({ message: 'Бронь успешно отменена.' });
    } catch (error) {
        console.error('Ошибка при удалении бронирования:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});
app.get('/adminAccount/:userId/bookings', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                b.id AS booking_id,
                COALESCE(u.first_name, gu.first_name) AS first_name,
                COALESCE(u.last_name, gu.last_name) AS last_name,
                b.booking_date,
                b.start_time,
                b.end_time,
                b.broom,
                b.broom_quantity, 
                b.towel,
                b.towel_quantity,
                b.hat,
                b.hat_quantity,
                b.sheets,
                b.sheets_quantity,
                b.price,
                CASE 
                    WHEN u.id IS NOT NULL THEN 'С аккаунтом'
                    WHEN gu.id IS NOT NULL THEN 'Без аккаунта'
                    ELSE 'Неизвестный'
                END AS user_type,
               CASE 
                    WHEN d.id IS NOT NULL THEN 'Действует акция'
                    ELSE 'Нет акции'
                END AS discount_status
            FROM 
                bookings b
            LEFT JOIN 
                users u ON b.user_id = u.id
            LEFT JOIN 
                guest_users gu ON b.user_id = gu.id
            LEFT JOIN 
                discounts d ON b.discount_id = d.id
        `);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Ошибка при получении бронирований:', error);
        res.status(500).json({ error: 'Ошибка при получении бронирований' });
    }
});
app.post('/adminAccount/:userId/intervals', async (req, res) => {
    const { booking_date, start_time, end_time } = req.body;

    try {
        const existingIntervalsResult = await pool.query(
            'SELECT start_time, end_time FROM booking_intervals WHERE booking_date = $1',
            [booking_date]
        );
        const existingIntervals = existingIntervalsResult.rows;
        let newStartTime = start_time;
        let newEndTime = end_time;
        let intervalsToUpdate = [];
        for (const interval of existingIntervals) {
            const intervalStart = interval.start_time;
            const intervalEnd = interval.end_time;
            if (
                (newStartTime <= intervalEnd && newEndTime >= intervalStart)
            ) {
                newStartTime = newStartTime < intervalStart ? newStartTime : intervalStart;
                newEndTime = newEndTime > intervalEnd ? newEndTime : intervalEnd;
                intervalsToUpdate.push(interval.start_time);
            }
        }
        if (intervalsToUpdate.length > 0) {
            await pool.query(
                'UPDATE booking_intervals SET start_time = $1, end_time = $2 WHERE booking_date = $3 AND start_time IN ($4)',
                [newStartTime, newEndTime, booking_date, ...intervalsToUpdate]
            );
            res.status(200).json({ message: 'Интервалы успешно объединены!' });
        } else {
            const result = await pool.query(
                'INSERT INTO booking_intervals (booking_date, start_time, end_time) VALUES ($1, $2, $3) RETURNING *',
                [booking_date, start_time, end_time]
            );
            res.status(201).json({ interval: result.rows[0] });
        }
    } catch (err) {
        res.status(500).json({ error: 'Ошибка при добавлении интервала' });
    }
});
app.get('/adminAccount/:userId/intervals', async (req, res) => {
    try {
        const intervalsResult = await pool.query('SELECT * FROM booking_intervals');
        const bookingsResult = await pool.query(`
            SELECT 
                b.id AS booking_id,
                u.first_name,
                u.last_name,
                b.booking_date,
                b.start_time,
                b.end_time,
                b.price
            FROM 
                bookings b
            JOIN 
                users u ON b.user_id = u.id
        `);

        res.status(200).json({
            intervals: intervalsResult.rows,
            bookings: bookingsResult.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка при получении интервалов и бронирований' });
    }
});
app.get('/adminAccount/:userId/availableIntervals/:bookingDate', async (req, res) => {
    const { bookingDate } = req.params;

    try {
        const existingIntervalsResult = await pool.query(
            'SELECT start_time, end_time FROM booking_intervals WHERE booking_date = $1',
            [bookingDate]
        );
        const existingIntervals = existingIntervalsResult.rows;
        const availableTimes = [];
        for (let hour = 8; hour <= 22; hour++) {
            const formattedHour = hour.toString().padStart(2, '0') + ':00';
            const isAvailable = !existingIntervals.some(interval => {
                const intervalStart = new Date(`${bookingDate}T${interval.start_time}`);
                const intervalEnd = new Date(`${bookingDate}T${interval.end_time}`);
                const proposedStart = new Date(`${bookingDate}T${formattedHour}`);

                return proposedStart >= intervalStart && proposedStart < intervalEnd;
            });

            if (isAvailable) {
                availableTimes.push({ start_time: formattedHour, end_time: `${hour + 2}:00` }); // Добавляем end_time
            }
        }

        res.status(200).json({ intervals: availableTimes });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при получении доступных интервалов' });
    }
});
app.delete('/adminAccount/:userId/intervals/:intervalId', async (req, res) => {
    const { intervalId } = req.params;

    try {
        const intervalResult = await pool.query(
            'SELECT booking_date, start_time FROM booking_intervals WHERE id = $1',
            [intervalId]
        );
        if (intervalResult.rows.length === 0) {
            return res.status(404).json({ error: 'Интервал не найден.' });
        }

        const { booking_date, start_time } = intervalResult.rows[0];
        const startTime = new Date(`${booking_date}T${start_time}`);

        if (startTime >= new Date()) {
            const bookingsResult = await pool.query(
                'SELECT * FROM bookings WHERE booking_date = $1',
                [booking_date]
            );

            if (bookingsResult.rows.length > 0) {
                return res.status(400).json({ error: 'Нельзя удалить интервал, так как на него есть бронь.' });
            }
        } else {
            await pool.query(
                'DELETE FROM booking_intervals WHERE id = $1',
                [intervalId]
            );
            return res.status(200).json({ message: 'Интервал успешно удален!' });
        }

        await pool.query(
            'DELETE FROM booking_intervals WHERE id = $1',
            [intervalId]
        );

        res.status(200).json({ message: 'Интервал успешно удален!' });
    } catch (err) {
        console.error('Ошибка при удалении интервала:', err);
        res.status(500).json({ error: 'Ошибка при удалении интервала' });
    }
});
app.get('/adminAccount/:userId/discounts/active', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM discounts`
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка при получении активных скидок:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.post('/adminAccount/:userId/discounts', async (req, res) => {
    const {
        description,
        discountType,
        applicableDays,
        validFrom,
        validTill,
        timeDiscountType,
        discountPercentage,
        applicableServices,
        servicePrices,
        freeServiceCounts,
        minServiceCounts,
    } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO discounts (
                description,
                discount_type,
                applicable_days,
                valid_from,
                valid_till,
                time_discount_type,
                discount_percentage,
                applicable_services,
                service_prices,
                free_service_counts,
                min_service_counts
            ) VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb) RETURNING *`,
            [
                description,
                discountType,
                JSON.stringify(applicableDays),
                validFrom,
                validTill,
                timeDiscountType,
                discountPercentage,
                JSON.stringify(applicableServices),
                JSON.stringify(servicePrices),
                JSON.stringify(freeServiceCounts),
                JSON.stringify(minServiceCounts),
            ]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка при добавлении скидки:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.put('/adminAccount/:userId/discounts/:discountId', async (req, res) => {
    const { discountId } = req.params;
    const {
        description,
        discountType,
        applicableDays,
        validFrom,
        validTill,
        timeDiscountType,
        discountPercentage,
        applicableServices,
        servicePrices,
        freeServiceCounts,
        minServiceCounts,
    } = req.body;
    console.log('Request body:', req.body);
    console.log('Request params:', req.params);

    try {
        const result = await pool.query(
            `UPDATE discounts
            SET 
                description = $1,
                discount_type = $2,
                applicable_days = $3::jsonb,
                valid_from = $4,
                valid_till = $5,
                time_discount_type = $6,
                discount_percentage = $7,
                applicable_services = $8::jsonb,
                service_prices = $9::jsonb,
                free_service_counts = $10::jsonb,
                min_service_counts = $11::jsonb
            WHERE id = $12
            RETURNING *`,
            [
                description,
                discountType,
                JSON.stringify(applicableDays),
                validFrom,
                validTill,
                timeDiscountType,
                discountPercentage,
                JSON.stringify(applicableServices),
                JSON.stringify(servicePrices),
                JSON.stringify(freeServiceCounts),
                JSON.stringify(minServiceCounts),
                discountId,
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Скидка не найдена' });
        }

        res.status(200).json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка при обновлении скидки:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
app.delete('/adminAccount/:userId/discounts/:discountId', async (req, res) => {
    const { discountId } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        await client.query(
            'UPDATE bookings SET discount_id = NULL WHERE discount_id = $1',
            [discountId]
        );

        const result = await client.query(
            'DELETE FROM discounts WHERE id = $1 RETURNING *',
            [discountId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Скидка не найдена' });
        }

        await client.query('COMMIT');

        res.status(200).json({ message: 'Скидка успешно удалена' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Ошибка при удалении скидки:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    } finally {
        client.release();
    }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
    console.log(`Разрешённые домены: ${allowedOrigins.join(', ')}`);
});