const { Loan, Book, User } = require('../models');
const { Op } = require('sequelize');

const loanController = {
    requestLoan: async (req, res) => {
        try {
            const { bookId, dataPrevistaDevolucao } = req.body;
            const userId = req.user.id;

            if (!bookId || !dataPrevistaDevolucao) {
                return res.status(400).json({
                    error: 'ID do livro e data prevista de devolução são obrigatórios.'
                });
            }

            const book = await Book.findByPk(bookId);
            if (!book) {
                return res.status(404).json({
                    error: 'Livro não encontrado.'
                });
            }

            if (book.quantidadeDisponivel <= 0) {
                return res.status(400).json({
                    error: 'Não há exemplares disponíveis deste livro no momento.'
                });
            }

            const existingLoan = await Loan.findOne({
                where: {
                    userId,
                    bookId,
                    status: { [Op.in]: ['pendente', 'aprovado', 'emprestado'] }
                }
            });

            if (existingLoan) {
                return res.status(400).json({
                    error: 'Você já possui uma solicitação ativa para este livro.'
                });
            }

            const loan = await Loan.create({
                userId,
                bookId,
                dataPrevistaDevolucao,
                status: 'pendente'
            });

            await book.update({
                quantidadeDisponivel: book.quantidadeDisponivel - 1
            });

            const loanWithDetails = await Loan.findByPk(loan.id, {
                include: [
                    { model: Book, as: 'livro' },
                    { model: User, as: 'usuario', attributes: { exclude: ['senha'] } }
                ]
            });

            res.status(201).json({
                message: 'Solicitação de empréstimo enviada com sucesso!',
                loan: loanWithDetails
            });
        } catch (error) {
            console.error('Erro ao solicitar empréstimo:', error);
            res.status(401).json({
                error: 'Erro ao solicitar empréstimo.'
            });
        }
    },

    getMyLoans: async (req, res) => {
        try {
            const userId = req.user.id;
            const { status } = req.query;

            const where = { userId };

            if (status) {
                where.status = status;
            }

            const loans = await Loan.findAll({
                where,
                include: [
                    { model: Book, as: 'livro' }
                ],
                order: [['createdAt', 'DESC']]
            });

            res.json(loans);
        } catch (error) {
            console.error('Erro ao buscar empréstimos:', error);
            res.status(401).json({
                error: 'Erro ao buscar empréstimos.'
            });
        }
    },

    requestReturn: async (req, res) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;

            const loan = await Loan.findByPk(id, {
                include: [
                    { model: Book, as: 'livro' }
                ]
            });

            if (!loan) {
                return res.status(404).json({
                    error: 'Empréstimo não encontrado.'
                });
            }

            if (loan.userId !== userId) {
                return res.status(403).json({
                    error: 'Você não tem permissão para solicitar devolução deste empréstimo.'
                });
            }

            if (loan.status !== 'emprestado') {
                return res.status(400).json({
                    error: 'Apenas empréstimos ativos podem ter devolução solicitada.'
                });
            }

            await loan.update({
                status: 'devolvido',
                dataDevolucao: new Date()
            });

            res.json({
                message: 'Devolução solicitada. Aguardando aprovação do bibliotecário.',
                loan
            });
        } catch (error) {
            console.error('Erro ao solicitar devolução:', error);
            res.status(500).json({
                error: 'Erro ao solicitar devolução.'
            });
        }
    },

    getAllLoans: async (req, res) => {
        try {
            const { status, userId, bookId } = req.query;

            const where = {};

            if (status) {
                where.status = status;
            }

            if (userId) {
                where.userId = userId;
            }

            if (bookId) {
                where.bookId = bookId;
            }

            const loans = await Loan.findAll({
                where,
                include: [
                    { model: Book, as: 'livro' },
                    { model: User, as: 'usuario', attributes: { exclude: ['senha'] } }
                ],
                order: [['createdAt', 'DESC']]
            });

            res.json(loans);
        } catch (error) {
            console.error('Erro ao buscar empréstimos:', error);
            res.status(500).json({
                error: 'Erro ao buscar empréstimos.'
            });
        }
    },

    approveLoan: async (req, res) => {
        try {
            const { id } = req.params;

            const loan = await Loan.findByPk(id, {
                include: [
                    { model: Book, as: 'livro' }
                ]
            });

            if (!loan) {
                return res.status(404).json({
                    error: 'Empréstimo não encontrado.'
                });
            }

            if (loan.status !== 'pendente') {
                return res.status(400).json({
                    error: 'Apenas empréstimos pendentes podem ser aprovados.'
                });
            }

            await loan.update({
                status: 'emprestado',
                dataEmprestimo: new Date()
            });

            res.json({
                message: 'Empréstimo aprovado com sucesso!',
                loan
            });
        } catch (error) {
            console.error('Erro ao aprovar empréstimo:', error);
            res.status(500).json({
                error: 'Erro ao aprovar empréstimo.'
            });
        }
    },

    rejectLoan: async (req, res) => {
        try {
            const { id } = req.params;
            const { observacoes } = req.body;

            const loan = await Loan.findByPk(id, {
                include: [
                    { model: Book, as: 'livro' }
                ]
            });

            if (!loan) {
                return res.status(404).json({
                    error: 'Empréstimo não encontrado.'
                });
            }

            if (loan.status !== 'pendente') {
                return res.status(400).json({
                    error: 'Apenas empréstimos pendentes podem ser rejeitados.'
                });
            }

            await loan.livro.update({
                quantidadeDisponivel: loan.livro.quantidadeDisponivel + 1
            });

            await loan.update({
                status: 'rejeitado',
                observacoes
            });

            res.json({
                message: 'Empréstimo rejeitado.',
                loan
            });
        } catch (error) {
            console.error('Erro ao rejeitar empréstimo:', error);
            res.status(401).json({
                error: 'Erro ao rejeitar empréstimo.'
            });
        }
    },

    approveReturn: async (req, res) => {
        try {
            const { id } = req.params;

            const loan = await Loan.findByPk(id, {
                include: [
                    { model: Book, as: 'livro' }
                ]
            });

            if (!loan) {
                return res.status(404).json({
                    error: 'Empréstimo não encontrado.'
                });
            }

            if (loan.status !== 'devolvido') {
                return res.status(400).json({
                    error: 'Apenas devoluções solicitadas podem ser aprovadas.'
                });
            }

            await loan.livro.update({
                quantidadeDisponivel: loan.livro.quantidadeDisponivel + 1
            });

            await loan.update({
                dataDevolucao: new Date()
            });

            res.json({
                message: 'Devolução aprovada com sucesso!',
                loan
            });
        } catch (error) {
            console.error('Erro ao aprovar devolução:', error);
            res.status(401).json({
                error: 'Erro ao aprovar devolução.'
            });
        }
    }
};

module.exports = loanController;
