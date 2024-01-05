const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 5001;
require('dotenv').config();

// Конфігурація та підключення до бази даних Sequelize
const sequelizeConfig = require('./sequelize.config');
const sequelize = new Sequelize(sequelizeConfig.development);

// Моделі для користувачів, категорій та записів
const User = sequelize.define('User', {
    user_id: {
        type: DataTypes.STRING,
        primaryKey: true,
    },
    user_name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    user_password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
});

const Category = sequelize.define('Category', {
    category_id: {
        type: DataTypes.STRING,
        primaryKey: true,
    },
    category_name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    visibility: {
        type: DataTypes.STRING,
    },
    owner_id: {
        type: DataTypes.STRING,
    },
});

const Record = sequelize.define('Record', {
    id: {
        type: DataTypes.STRING,
        primaryKey: true,
    },
    user_id: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    category_id: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    creation_data: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    cost: {
        type: DataTypes.STRING,
        allowNull: false,
    },
});

// Використання bodyParser для обробки JSON-даних в запитах
app.use(bodyParser.json());

// Задання секретного ключа для підпису та перевірки JWT-токенів
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

// Middleware для перевірки JWT-токена
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Опис маршрутів та їх обробники

// Головна сторінка
app.get('/', (req, res) => {
    res.send('Це домашній проект для курсу Node.js!');
});

// Реєстрація нового користувача
app.post('/register', [
    check('user_name').notEmpty(),
    check('user_id').notEmpty(),
    check('user_password').notEmpty(),
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { user_name, user_id, user_password } = req.body;

        const existingUser = await User.findOne({ where: { user_name } });
        if (existingUser) {
            return res.status(409).json({ error: 'Користувач з таким ім\'ям вже існує' });
        }

        const hashedPassword = await bcrypt.hash(user_password, 10);

        await User.create({ user_name, user_password: hashedPassword, user_id });

        res.status(201).json({ message: 'Користувач створений!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Вхід користувача
app.post('/login', async (req, res) => {
    try {
        const { user_name, user_password } = req.body;

        const user = await User.findOne({ where: { user_name } });
        if (!user || !(await bcrypt.compare(user_password, user.user_password))) {
            return res.status(401).json({ error: 'Неправильне ім\'я користувача або пароль' });
        }

        const accessToken = jwt.sign({ user_id: user.user_id }, JWT_SECRET_KEY);
        res.json({ access_token: accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Отримання списку користувачів
app.get('/users', async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: { exclude: ['user_password'] }
        });
        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Створення нової категорії
app.post('/category', authenticateToken, async (req, res) => {
    try {
        const { category_id, category_name, visibility, owner_id } = req.body;
        const current_user_id = req.user.user_id;

        const newCategory = await Category.create({
            category_id,
            category_name,
            visibility,
            owner_id,
        });

        if (newCategory.owner_id !== current_user_id) {
            return res.status(403).json({ error: 'Ви не маєте права вказувати іншого власника для категорії' });
        }

        res.status(201).json(newCategory);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Отримання всіх категорій
app.get('/categories', authenticateToken, async (req, res) => {
    try {
        const categories = await Category.findAll();
        res.json(categories);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Отримання конкретної категорії за ідентифікатором
app.get('/category/:category_id', authenticateToken, async (req, res) => {
    try {
        const category = await Category.findByPk(req.params.category_id);
        if (category) {
            res.json(category);
        } else {
            res.status(404).json({ error: 'Категорія не знайдена' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Видалення категорії за ідентифікатором
app.delete('/category/:category_id', authenticateToken, async (req, res) => {
    try {
        const category = await Category.findByPk(req.params.category_id);
        const current_user_id = req.user.user_id;

        if (category) {
            if (category.owner_id !== current_user_id) {
                return res.status(403).json({ error: 'Ви не маєте права видаляти цю категорію' });
            }

            await category.destroy();
            res.json({ message: 'Категорію успішно видалено' });
        } else {
            res.status(404).json({ error: 'Категорія не знайдена' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Створення нового запису
app.post('/record', authenticateToken, async (req, res) => {
    try {
        const { id, user_id, category_id, creation_data, cost } = req.body;
        const current_user_id = req.user.user_id;

        const category = await Category.findByPk(category_id);
        if (!category) {
            return res.status(404).json({ error: 'Категорія не знайдена' });
        }

        const visibility = category.visibility;
        if (visibility === 'private' && user_id !== current_user_id) {
            return res.status(403).json({ error: 'Ви не маєте права використовувати цю категорію' });
        }

        const newRecord = await Record.create({
            id,
            user_id,
            category_id,
            creation_data,
            cost,
        });

        res.status(201).json(newRecord);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Отримання всіх записів (з необов'язковими фільтрами для user_id та category_id)
app.get('/records', authenticateToken, async (req, res) => {
    try {
        const { user_id, category_id } = req.query;

        let records;
        if (user_id) {
            records = await Record.findAll({ where: { user_id } });
        } else if (category_id) {
            records = await Record.findAll({ where: { category_id } });
        } else {
            records = await Record.findAll();
        }

        res.json(records);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Видалення запису за ідентифікатором
app.delete('/record/:record_id', authenticateToken, async (req, res) => {
    try {
        const record = await Record.findByPk(req.params.record_id);
        const current_user_id = req.user.user_id;

        if (record) {
            if (record.user_id !== current_user_id) {
                return res.status(403).json({ error: 'Ви не маєте права видаляти цей запис' });
            }

            await record.destroy();
            res.json({ message: 'Запис успішно видалено' });
        } else {
            res.status(404).json({ error: 'Запис не знайдено' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Внутрішня помилка сервера' });
    }
});

// Запуск сервера
sequelize.sync().then(() => {
    app.listen(PORT, () => {
        console.log(`Сервер працює на порті ${PORT}`);
    });
});
