const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { testConnection } = require('./config/database');
const { syncDatabase } = require('./models');

const authRoutes = require('./routes/authRoutes');
const bookRoutes = require('./routes/bookRoutes');
const loanRoutes = require('./routes/loanRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.json({
        message: 'API do Sistema de Biblioteca',
        version: '1.0.0',
        endpoints: {
            auth: '/api/auth',
            books: '/api/books',
            loans: '/api/loans'
        }
    });
});

app.use('/api/auth', authRoutes);
app.use('/api/books', bookRoutes);
app.use('/api/loans', loanRoutes);

app.use((req, res) => {
    res.status(404).json({
        error: 'Rota não encontrada.'
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'ERRO INTERNO NO SERVIDOR'
    });
});

const startServer = async () => {
    try {
        await testConnection();
        await syncDatabase();

        app.listen(PORT, () => {
            console.log(`\n Servidor rodando na porta ${PORT}`);
            console.log(` Acesse: http://localhost:${PORT}`);
        });
    } catch (error) {
      error.status=500 
      console.error('Erro ao iniciar servidor:', error);
      process.exit(1);
    }
};

startServer();

module.exports = app;
