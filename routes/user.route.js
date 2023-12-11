const express = require('express')
const router = express.Router();
const {registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getAllUsers, loginStatus, changeUserRole} = require('../controllers/user.controller');
const { protect, adminOnly, authorOnly } = require('../middlewares/auth.middleware');

router.post('/register',registerUser)
router.get('/login',loginUser)
router.get('/logout',logoutUser)
router.get('/get-user',protect,getUser)
router.patch('/update-user',protect,updateUser)

router.delete('/:id',protect,adminOnly,deleteUser)
router.get('/get-all-users',protect,authorOnly,getAllUsers)
router.get('/login-status',loginStatus)
router.post('/change-user-role',protect,adminOnly,changeUserRole)

module.exports = router;