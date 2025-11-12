const express = require('express');
const router = express.Router();
const bookController = require('../controllers/bookController');
const { authMiddleware, isBibliotecario } = require('../middlewares/auth');

router.get('/', authMiddleware, bookController.getAll);
router.get('/:id', authMiddleware, bookController.getById);

router.post('/', authMiddleware, isBibliotecario, bookController.create);
router.put('/:id', authMiddleware, isBibliotecario, bookController.update);
router.delete('/:id', authMiddleware, isBibliotecario, bookController.delete);

module.exports = router;
