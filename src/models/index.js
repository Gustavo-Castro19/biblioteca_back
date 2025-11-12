const { sequelize } = require('../config/database');
const User = require('./User');
const Book = require('./Book');
const Loan = require('./Loan');

const syncDatabase = async () => {
    try {
        await sequelize.sync({ alter: true });
        console.log(' Modelos sincronizados com o banco de dados.');
    } catch (error) {
        console.error(' Erro ao sincronizar modelos:', error);
    }
};

module.exports = {
    User,
    Book,
    Loan,
    syncDatabase
};
