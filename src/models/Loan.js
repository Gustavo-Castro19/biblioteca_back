const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const User = require('./User');
const Book = require('./Book');

const Loan = sequelize.define('Loan', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
            model: 'usuarios',
            key: 'id'
        }
    },
    bookId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
            model: 'livros',
            key: 'id'
        }
    },
    dataEmprestimo: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
    },
    dataPrevistaDevolucao: {
        type: DataTypes.DATE,
        allowNull: false
    },
    dataDevolucao: {
        type: DataTypes.DATE,
        allowNull: true
    },
    status: {
        type: DataTypes.ENUM('pendente', 'aprovado', 'emprestado', 'devolvido', 'rejeitado'),
        allowNull: false,
        defaultValue: 'pendente'
    },
    observacoes: {
        type: DataTypes.TEXT,
        allowNull: true
    }
}, {
    tableName: 'emprestimos',
    timestamps: true
});

Loan.belongsTo(User, { foreignKey: 'userId', as: 'usuario' });
Loan.belongsTo(Book, { foreignKey: 'bookId', as: 'livro' });
User.hasMany(Loan, { foreignKey: 'userId', as: 'emprestimos' });
Book.hasMany(Loan, { foreignKey: 'bookId', as: 'emprestimos' });

module.exports = Loan;
