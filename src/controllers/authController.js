const jwt = require('jsonwebtoken');
const { User } = require('../models');

const authController = {
    register: async (req, res) => {
        try {
            const { nome, email, senha, tipo, telefone, endereco } = req.body;
          const emailIsValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            if (!nome || !emailIsValid || !senha ) {
                return res.status(400).json({
                    error: 'Nome, email e senha são obrigatórios.\n'
                });
            }

            const userExists = await User.findOne({ where: { email } });
            if (userExists) {
                return res.status(400).json({
                    error: 'Email já cadastrado.'
                });
            }

            const user = await User.create({
                nome,
                email,
                senha,
                tipo: tipo ?? 'leitor',
                telefone,
                endereco
            });

            const userResponse = user.toJSON();
            delete userResponse.senha;

            res.status(201).json({
                message: 'Usuário cadastrado com sucesso!',
                user: userResponse
            });
        } catch (error) {
            console.error('Erro ao registrar usuário:', error);
            res.status(401).json({
                error: 'Erro ao cadastrar usuário.'
            });
        }
    },

    login: async (req, res) => {
        try {
            const { email, senha } = req.body;

            if (!email || !senha) {
                return res.status(400).json({
                    error: 'Email e senha são obrigatórios.'
                });
            }

            const user = await User.findOne({ where: { email } });
            if (!user) {
                return res.status(401).json({
                    error: 'Credenciais inválidas.'
                });
            }

            if (!user.ativo) {
                return res.status(401).json({
                    error: 'Usuário inativo. Entre em contato com o administrador.'
                });
            }

            const senhaValida = await user.validarSenha(senha);
            if (!senhaValida) {
                return res.status(401).json({
                    error: 'Credenciais inválidas.'
                });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    email: user.email,
                    tipo: user.tipo
                },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN }
            );

            const userResponse = user.toJSON();
            delete userResponse.senha;

            res.json({
                message: 'Login realizado com sucesso!',
                token,
                user: userResponse
            });
        } catch (error) {
            console.error('Erro ao fazer login:', error);
            res.status(401).json({
                error: 'Erro ao fazer login.'
            });
        }
    },

    getProfile: async (req, res) => {
        try {
            const user = await User.findByPk(req.user.id, {
                attributes: { exclude: ['senha'] }
            });

            if (!user) {
                return res.status(404).json({
                    error: 'Usuário não encontrado.'
                });
            }

            res.json(user);
        } catch (error) {
            console.error('Erro ao buscar perfil:', error);
            res.status(401).json({
                error: 'Erro ao buscar perfil.'
            });
        }
    }
};

module.exports = authController;
