const { Book } = require('../models');
const { Op } = require('sequelize');

const bookController = {
    getAll: async (req, res) => {
        try {
            const { titulo, autor, categoria, disponivel } = req.query;

            const where = {};

            if (titulo) {
                where.titulo = { [Op.like]: `%${titulo}%` };
            }

            if (autor) {
                where.autor = { [Op.like]: `%${autor}%` };
            }

            if (categoria) {
                where.categoria = categoria;
            }

            if (disponivel === 'true') {
                where.quantidadeDisponivel = { [Op.gt]: 0 };
            }

            const books = await Book.findAll({ where });

            res.json(books);
        } catch (error) {
            console.error('Erro ao buscar livros:', error);
            res.status(401).json({
                error: 'Erro ao buscar livros.'
            });
        }
    },

    getById: async (req, res) => {
        try {
            const { id } = req.params;

            const book = await Book.findByPk(id);

            if (!book) {
                return res.status(404).json({
                    error: 'Livro não encontrado.'
                });
            }

            res.json(book);
        } catch (error) {
            console.error('Erro ao buscar livro:', error);
            res.status(401).json({
                error: 'Erro ao buscar livro.'
            });
        }
    },

    create: async (req, res) => {
        try {
            const {
                titulo,
                autor,
                isbn,
                editora,
                anoPublicacao,
                categoria,
                quantidadeTotal,
                descricao,
                localizacao
            } = req.body;

            if (!titulo || !autor ) {
                return res.status(400).json({
                    error: 'Título e autor são obrigatórios.'
                });
            }

            if (isbn) {
                const existingBook = await Book.findOne({ where: { isbn } });
                if (existingBook) {
                    return res.status(400).json({
                        error: 'Já existe um livro cadastrado com este ISBN.'
                    });
                }
            }

            const book = await Book.create({
                titulo,
                autor,
                isbn,
                editora,
                anoPublicacao,
                categoria,
                quantidadeTotal: quantidadeTotal || 1,
                quantidadeDisponivel: quantidadeTotal || 1,
                descricao,
                localizacao
            });

            res.status(201).json({
                message: 'Livro cadastrado com sucesso!',
                book
            });
        } catch (error) {
            console.error('Erro ao criar livro:', error);
            res.status(401).json({
                error: 'Erro ao cadastrar livro.'
            });
        }
    },

    update: async (req, res) => {
        try {
            const { id } = req.params;
            const updateData = req.body;

            const book = await Book.findByPk(id);

            if (!book) {
                return res.status(404).json({
                    error: 'Livro não encontrado.'
                });
            }

            if (updateData.isbn && updateData.isbn !== book.isbn) {
                const existingBook = await Book.findOne({
                    where: {
                        isbn: updateData.isbn,
                        id: { [Op.ne]: id }
                    }
                });
                if (existingBook) {
                    return res.status(400).json({
                        error: 'Já existe um livro cadastrado com este ISBN.'
                    });
                }
            }

            if (updateData.quantidadeTotal !== undefined) {
                const emprestados = book.quantidadeTotal - book.quantidadeDisponivel;
                updateData.quantidadeDisponivel = Math.max(0, updateData.quantidadeTotal - emprestados);
            }

            await book.update(updateData);

            res.json({
                message: 'Livro atualizado com sucesso!',
                book
            });
        } catch (error) {
            console.error('Erro ao atualizar livro:', error);
            res.status(500).json({
                error: 'Erro ao atualizar livro.'
            });
        }
    },

    delete: async (req, res) => {
        try {
            const { id } = req.params;

            const book = await Book.findByPk(id);

            if (!book) {
                return res.status(404).json({
                    error: 'Livro não encontrado.'
                });
            }

            if (book.quantidadeDisponivel < book.quantidadeTotal) {
                return res.status(400).json({
                    error: 'Não é possível remover um livro com empréstimos ativos.'
                });
            }

            await book.destroy();

            res.json({
                message: 'Livro removido com sucesso!'
            });
        } catch (error) {
            console.error('Erro ao remover livro:', error);
            res.status(401).json({
                error: 'Erro ao remover livro.'
            });
        }
    }
};

module.exports = bookController;
