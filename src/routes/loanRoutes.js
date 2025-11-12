const express = require('express');
const router = express.Router();
const loanController = require('../controllers/loanController');
const { authMiddleware, isBibliotecario, isLeitor } = require('../middlewares/auth');

router.post('/request', authMiddleware, loanController.requestLoan);
router.get('/my-loans', authMiddleware, loanController.getMyLoans);
router.put('/:id/return', authMiddleware, loanController.requestReturn);

router.get('/', authMiddleware, isBibliotecario, loanController.getAllLoans);
router.put('/:id/approve', authMiddleware, isBibliotecario, loanController.approveLoan);
router.put('/:id/reject', authMiddleware, isBibliotecario, loanController.rejectLoan);
router.put('/:id/approve-return', authMiddleware, isBibliotecario, loanController.approveReturn);

module.exports = router;
