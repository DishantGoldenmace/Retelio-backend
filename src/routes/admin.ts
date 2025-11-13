import { Router } from 'express';
import { login, dashboard, listVendors, updateVendorStatus } from '../controllers/admin'

import { authAdmin } from '../middlewares/admin'

const router = Router();

router.post('/login', login);

router.get('/dashboard', authAdmin, dashboard);

router.get('/list-vendors/:status', authAdmin, listVendors);

router.put('/update-vendor-status/:id', authAdmin, updateVendorStatus);

export default router;