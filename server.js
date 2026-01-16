const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: '*',
    credentials: true
}));
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
  });
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// MongoDB Atlas Connection - Updated for Mongoose 6+
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://riyadammmeri:OmGe6UeG1Q0hVJEq@ac-ujqhcf3-shard-00-00.7xu8hz3.mongodb.net:27017,ac-ujqhcf3-shard-00-01.7xu8hz3.mongodb.net:27017,ac-ujqhcf3-shard-00-02.7xu8hz3.mongodb.net:27017/?ssl=true&replicaSet=atlas-3anew8-shard-0&authSource=admin&retryWrites=true&w=majority&appName=Cluster0';
// const MONGODB_URI = 'mongodb://localhost:27017/student-organization';
const connectDB = async () => {
    try {
        // 对于Mongoose 6+，移除useNewUrlParser和useUnifiedTopology
        await mongoose.connect(MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        console.log('✅ MongoDB Atlas Connected Successfully');
        
        mongoose.connection.on('error', err => {
            console.error('❌ MongoDB connection error:', err);
        });
        
        mongoose.connection.on('disconnected', () => {
            console.log('⚠️ MongoDB disconnected');
        });
        
        process.on('SIGINT', async () => {
            await mongoose.connection.close();
            console.log('👋 MongoDB connection closed through app termination');
            process.exit(0);
        });
        
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        // 重新尝试连接
        setTimeout(connectDB, 5000);
    }
};

connectDB();

// MongoDB Schemas and Models

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String },
    faculty: { type: String },
    studyLevel: { type: String },
    universityId: { type: String, unique: true },
    role: { 
        type: String, 
        enum: ['admin', 'organization_head', 'member', 'guest'], 
        default: 'member' 
    },
    department: { type: String },
    position: { type: String },
    points: { type: Number, default: 0 },
    joinDate: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    profileImage: { type: String },
    isActive: { type: Boolean, default: true },
    skills: [String],
    interests: [String]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false },
    attachments: [String]
}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

// Task Schema
const taskSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    department: { type: String },
    priority: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'urgent'], 
        default: 'medium' 
    },
    status: { 
        type: String, 
        enum: ['pending', 'in_progress', 'completed', 'cancelled'], 
        default: 'pending' 
    },
    deadline: { type: Date },
    points: { type: Number, default: 10 },
    completedAt: { type: Date },
    feedback: { type: String },
    rating: { type: Number, min: 1, max: 5 }
}, { timestamps: true });

const Task = mongoose.model('Task', taskSchema);

// Activity Schema
const activitySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    type: { 
        type: String, 
        enum: ['academic', 'cultural', 'sport', 'social', 'training', 'meeting'],
        default: 'meeting' 
    },
    organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    department: { type: String },
    location: { type: String },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    maxParticipants: { type: Number },
    points: { type: Number, default: 20 },
    status: { 
        type: String, 
        enum: ['planned', 'ongoing', 'completed', 'cancelled'], 
        default: 'planned' 
    },
    resources: [String],
    notes: { type: String }
}, { timestamps: true });

const Activity = mongoose.model('Activity', activitySchema);

// Evaluation Schema
const evaluationSchema = new mongoose.Schema({
    evaluator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    evaluatedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    task: { type: mongoose.Schema.Types.ObjectId, ref: 'Task' },
    activity: { type: mongoose.Schema.Types.ObjectId, ref: 'Activity' },
    criteria: [{
        name: String,
        score: { type: Number, min: 1, max: 10 },
        weight: { type: Number, default: 1 }
    }],
    totalScore: { type: Number },
    feedback: { type: String },
    date: { type: Date, default: Date.now },
    pointsAwarded: { type: Number, default: 0 }
}, { timestamps: true });

const Evaluation = mongoose.model('Evaluation', evaluationSchema);

// HR Resource Schema
const hrResourceSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { 
        type: String, 
        enum: ['document', 'template', 'policy', 'guideline', 'form'] 
    },
    category: { type: String },
    description: { type: String },
    fileUrl: { type: String },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadDate: { type: Date, default: Date.now },
    department: { type: String },
    tags: [String],
    isPublic: { type: Boolean, default: true }
}, { timestamps: true });

const HRResource = mongoose.model('HRResource', hrResourceSchema);

// Department Schema
const departmentSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String },
    head: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Department = mongoose.model('Department', departmentSchema);
const base64ImageSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    imageType: { type: String, enum: ['profile', 'chat', 'activity', 'task'], required: true },
    mimeType: { type: String, required: true },
    data: { type: String, required: true }, // Base64 encoded image
    size: { type: Number, required: true },
    uploadedAt: { type: Date, default: Date.now }
});

const Base64Image = mongoose.model('Base64Image', base64ImageSchema);

// File Upload Configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)){
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('File type not allowed. Allowed types: images, PDF, Word, text'));
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'student-organization-secret-key-2024';

// Middleware for Authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Middleware for Admin Authorization
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin' && req.user.role !== 'organization_head') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Middleware for logging
const requestLogger = (req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
};

app.use(requestLogger);

// Routes

// route to page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
// 1. HEALTH CHECK
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'Student Organization Management API is running',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});
app.put('/api/users/:id/toggle-status', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { isActive } = req.body;
        
        if (typeof isActive !== 'boolean') {
            return res.status(400).json({ 
                success: false,
                message: 'يجب إرسال حالة الحساب (true/false)' 
            });
        }
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { isActive },
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        
        const action = isActive ? 'تفعيل' : 'تعطيل';
        res.json({ 
            success: true,
            message: `تم ${action} حساب المستخدم بنجاح`,
            user 
        });
    } catch (error) {
        console.error('Toggle user status error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في تغيير حالة الحساب',
            error: error.message 
        });
    }
});

// إعادة تعيين كلمة المرور (للمسؤول)
app.post('/api/users/:id/reset-password', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { newPassword } = req.body;
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ 
                success: false,
                message: 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { password: hashedPassword },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'تم إعادة تعيين كلمة المرور بنجاح',
            user 
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إعادة تعيين كلمة المرور',
            error: error.message 
        });
    }
});

// 2. AUTHENTICATION ROUTES
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, fullName, email, universityId, faculty, studyLevel, phone } = req.body;
        
        // Validate required fields
        if (!username || !password || !fullName || !email || !universityId) {
            return res.status(400).json({ 
                message: 'Missing required fields: username, password, fullName, email, universityId' 
            });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ username }, { email }, { universityId }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                message: 'Username, email or university ID already exists' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            username,
            password: hashedPassword,
            fullName,
            email,
            universityId,
            phone,
            faculty: faculty || 'كلية الآداب واللغات',
            studyLevel: studyLevel || 'سنة أولى ليسانس',
            role: 'member'
        });
        
        await user.save();
        
        // Generate token
        const token = jwt.sign(
            { 
                id: user._id, 
                username: user.username, 
                role: user.role,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            success: true,
            message: 'تم تسجيل الحساب بنجاح',
            token,
            user: {
                id: user._id,
                username: user.username,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                points: user.points,
                faculty: user.faculty,
                studyLevel: user.studyLevel
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال اسم المستخدم وكلمة المرور' 
            });
        }
        
        // Find user by username or email
        const user = await User.findOne({ 
            $or: [{ username }, { email: username }] 
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: 'اسم المستخدم أو البريد الإلكتروني غير صحيح' 
            });
        }
        
        if (!user.isActive) {
            return res.status(403).json({ 
                success: false,
                message: 'الحساب معطل. يرجى التواصل مع الإدارة' 
            });
        }
        
        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false,
                message: 'كلمة المرور غير صحيحة' 
            });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = jwt.sign(
            { 
                id: user._id, 
                username: user.username, 
                role: user.role,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            message: 'تم تسجيل الدخول بنجاح',
            token,
            user: {
                id: user._id,
                username: user.username,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                points: user.points,
                profileImage: user.profileImage,
                faculty: user.faculty,
                studyLevel: user.studyLevel,
                department: user.department,
                position: user.position
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

// 3. USER MANAGEMENT ROUTES
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find({ isActive: true })
            .select('-password')
            .sort({ points: -1, createdAt: -1 });
        res.json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        res.json({
            success: true,
            user
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        res.json({
            success: true,
            user
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const { points, role, department, position, skills, interests } = req.body;
        
        // Check permissions
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            return res.status(403).json({ 
                success: false,
                message: 'غير مصرح لك بتعديل هذا المستخدم' 
            });
        }
        
        const updateData = {};
        if (points !== undefined && req.user.role === 'admin') updateData.points = points;
        if (role && req.user.role === 'admin') updateData.role = role;
        if (department) updateData.department = department;
        if (position) updateData.position = position;
        if (skills) updateData.skills = skills;
        if (interests) updateData.interests = interests;
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'تم تحديث بيانات المستخدم',
            user 
        });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في السيرفر',
            error: error.message 
        });
    }
});

app.post('/api/users/upload-profile-image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false,
                message: 'لم يتم رفع أي صورة' 
            });
        }
        
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { profileImage: `/uploads/${req.file.filename}` },
            { new: true }
        ).select('-password');
        
        res.json({ 
            success: true,
            message: 'تم تحديث صورة الملف الشخصي',
            user 
        });
    } catch (error) {
        console.error('Upload profile image error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في رفع الصورة',
            error: error.message 
        });
    }
});

// 4. MESSAGING ROUTES
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { receiverId, content } = req.body;
        
        if (!receiverId || !content) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال المستلم ومحتوى الرسالة' 
            });
        }
        
        // Check if receiver exists
        const receiver = await User.findById(receiverId);
        if (!receiver) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم المستقبل غير موجود' 
            });
        }
        
        const message = new Message({
            sender: req.user.id,
            receiver: receiverId,
            content
        });
        
        await message.save();
        
        // Populate sender and receiver info
        await message.populate('sender', 'username fullName profileImage');
        await message.populate('receiver', 'username fullName profileImage');
        
        res.status(201).json({ 
            success: true,
            message: 'تم إرسال الرسالة بنجاح',
            data: message 
        });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إرسال الرسالة',
            error: error.message 
        });
    }
});
app.post('/api/users/upload-profile-image-base64', authenticateToken, async (req, res) => {
    try {
        const { imageData, mimeType } = req.body;
        
        if (!imageData || !mimeType) {
            return res.status(400).json({ 
                success: false,
                message: 'بيانات الصورة ونوعها مطلوبة' 
            });
        }
        
        // التحقق من حجم الصورة (5MB كحد أقصى)
        const imageSize = Buffer.byteLength(imageData, 'base64');
        const maxSize = 5 * 1024 * 1024; // 5MB
        
        if (imageSize > maxSize) {
            return res.status(400).json({ 
                success: false,
                message: 'حجم الصورة يجب أن يكون أقل من 5MB' 
            });
        }
        
        // التحقق من نوع الصورة
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!allowedMimeTypes.includes(mimeType)) {
            return res.status(400).json({ 
                success: false,
                message: 'نوع الصورة غير مدعوم. المسموح: JPEG, PNG, GIF, WebP' 
            });
        }
        
        // حفظ الصورة كـ Base64
        const base64Image = new Base64Image({
            user: req.user.id,
            imageType: 'profile',
            mimeType,
            data: imageData,
            size: imageSize
        });
        
        await base64Image.save();
        
        // تحديث صورة البروفايل للمستخدم
        const imageUrl = `data:${mimeType};base64,${imageData}`;
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { profileImage: imageUrl },
            { new: true }
        ).select('-password');
        
        res.json({ 
            success: true,
            message: 'تم تحديث صورة الملف الشخصي بنجاح',
            user,
            imageId: base64Image._id
        });
    } catch (error) {
        console.error('Upload profile image base64 error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في رفع صورة الملف الشخصي',
            error: error.message 
        });
    }
});

// تحميل صورة للمحادثات كـ Base64
app.post('/api/messages/:messageId/upload-image', authenticateToken, async (req, res) => {
    try {
        const { messageId } = req.params;
        const { imageData, mimeType } = req.body;
        
        if (!imageData || !mimeType) {
            return res.status(400).json({ 
                success: false,
                message: 'بيانات الصورة ونوعها مطلوبة' 
            });
        }
        
        // التحقق من وجود الرسالة
        const message = await Message.findById(messageId);
        if (!message) {
            return res.status(404).json({ 
                success: false,
                message: 'الرسالة غير موجودة' 
            });
        }
        
        // التحقق من صلاحية المستخدم
        if (message.sender.toString() !== req.user.id) {
            return res.status(403).json({ 
                success: false,
                message: 'غير مصرح لك بإرفاق صورة بهذه الرسالة' 
            });
        }
        
        // حفظ الصورة كـ Base64
        const imageSize = Buffer.byteLength(imageData, 'base64');
        const base64Image = new Base64Image({
            user: req.user.id,
            imageType: 'chat',
            mimeType,
            data: imageData,
            size: imageSize
        });
        
        await base64Image.save();
        
        // إضافة الصورة إلى الرسالة
        const imageUrl = `data:${mimeType};base64,${imageData}`;
        message.attachments.push(imageUrl);
        await message.save();
        
        res.json({ 
            success: true,
            message: 'تم رفع الصورة بنجاح',
            message,
            imageId: base64Image._id
        });
    } catch (error) {
        console.error('Upload message image error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في رفع صورة المحادثة',
            error: error.message 
        });
    }
});

// جلب الصورة بواسطة الـ ID
app.get('/api/images/:id', authenticateToken, async (req, res) => {
    try {
        const image = await Base64Image.findById(req.params.id);
        
        if (!image) {
            return res.status(404).json({ 
                success: false,
                message: 'الصورة غير موجودة' 
            });
        }
        
        // التحقق من صلاحية المستخدم لمشاهدة الصورة
        if (image.user.toString() !== req.user.id) {
            return res.status(403).json({ 
                success: false,
                message: 'غير مصرح لك بمشاهدة هذه الصورة' 
            });
        }
        
        res.json({
            success: true,
            image: {
                id: image._id,
                imageType: image.imageType,
                mimeType: image.mimeType,
                data: image.data,
                size: image.size,
                uploadedAt: image.uploadedAt
            }
        });
    } catch (error) {
        console.error('Get image error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب الصورة',
            error: error.message 
        });
    }
});

// حذف الصورة
app.delete('/api/images/:id', authenticateToken, async (req, res) => {
    try {
        const image = await Base64Image.findById(req.params.id);
        
        if (!image) {
            return res.status(404).json({ 
                success: false,
                message: 'الصورة غير موجودة' 
            });
        }
        
        // التحقق من صلاحية المستخدم لحذف الصورة
        if (image.user.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false,
                message: 'غير مصرح لك بحذف هذه الصورة' 
            });
        }
        
        await Base64Image.findByIdAndDelete(req.params.id);
        
        res.json({ 
            success: true,
            message: 'تم حذف الصورة بنجاح'
        });
    } catch (error) {
        console.error('Delete image error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في حذف الصورة',
            error: error.message 
        });
    }
});

// إحصائيات الإدارة المتقدمة
app.get('/api/admin/statistics', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // إحصاءات المستخدمين
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const adminCount = await User.countDocuments({ role: 'admin' });
        const orgHeadCount = await User.countDocuments({ role: 'organization_head' });
        
        // إحصاءات المهام
        const tasksByStatus = await Task.aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } }
        ]);
        
        // إحصاءات الأنشطة
        const activitiesByStatus = await Activity.aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } }
        ]);
        
        // إحصاءات الصور
        const imagesByType = await Base64Image.aggregate([
            { $group: { _id: '$imageType', count: { $sum: 1 }, totalSize: { $sum: '$size' } } }
        ]);
        
        // المستخدمون النشطون (آخر 7 أيام)
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        
        const activeUsersLast7Days = await User.countDocuments({
            lastLogin: { $gte: sevenDaysAgo },
            isActive: true
        });
        
        res.json({
            success: true,
            statistics: {
                users: {
                    total: totalUsers,
                    active: activeUsers,
                    inactive: totalUsers - activeUsers,
                    admins: adminCount,
                    organizationHeads: orgHeadCount,
                    activeLast7Days: activeUsersLast7Days
                },
                tasks: {
                    byStatus: tasksByStatus
                },
                activities: {
                    byStatus: activitiesByStatus
                },
                images: {
                    byType: imagesByType
                }
            }
        });
    } catch (error) {
        console.error('Admin statistics error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جدد إحصائيات الإدارة',
            error: error.message 
        });
    }
});

// نسخ احتياطي للبيانات
app.get('/api/admin/backup', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const backupData = {
            timestamp: new Date().toISOString(),
            users: await User.find().select('-password').lean(),
            tasks: await Task.find().lean(),
            activities: await Activity.find().lean(),
            messages: await Message.find().limit(1000).lean(),
            departments: await Department.find().lean(),
            base64Images: await Base64Image.find().limit(1000).lean(),
            metadata: {
                userCount: await User.countDocuments(),
                taskCount: await Task.countDocuments(),
                activityCount: await Activity.countDocuments(),
                messageCount: await Message.countDocuments(),
                imageCount: await Base64Image.countDocuments()
            }
        };
        
        res.json({
            success: true,
            message: 'تم إنشاء النسخة الاحتياطية بنجاح',
            backup: backupData
        });
    } catch (error) {
        console.error('Backup error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء النسخة الاحتياطية',
            error: error.message 
        });
    }
});

// استعادة من نسخة احتياطية (نموذج مبسط)
app.post('/api/admin/restore', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { backupData } = req.body;
        
        if (!backupData) {
            return res.status(400).json({ 
                success: false,
                message: 'بيانات النسخة الاحتياطية مطلوبة' 
            });
        }
        
        // التحقق من صلاحية البيانات
        if (!backupData.timestamp || !backupData.users || !Array.isArray(backupData.users)) {
            return res.status(400).json({ 
                success: false,
                message: 'بيانات النسخة الاحتياطية غير صالحة' 
            });
        }
        
        // ملاحظة: في نظام حقيقي، يجب اتخاذ احتياطات أكبر قبل استعادة البيانات
        res.json({
            success: true,
            message: 'وظيفة الاستعادة متاحة للمسؤولين فقط. الرجاء الاتصال بالدعم الفني للاستعادة الكاملة.',
            backupTimestamp: backupData.timestamp,
            dataSummary: {
                users: backupData.users.length,
                tasks: backupData.tasks?.length || 0,
                activities: backupData.activities?.length || 0
            }
        });
    } catch (error) {
        console.error('Restore error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في استعادة النسخة الاحتياطية',
            error: error.message 
        });
    }
});

// البحث المتقدم في المستخدمين
app.get('/api/admin/users/search', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { 
            search, 
            role, 
            faculty, 
            department,
            minPoints,
            maxPoints,
            isActive,
            sortBy = 'createdAt',
            sortOrder = 'desc',
            page = 1,
            limit = 20 
        } = req.query;
        
        const query = {};
        
        // بحث نصي
        if (search) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { fullName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { universityId: { $regex: search, $options: 'i' } }
            ];
        }
        
        // تصفية حسب الدور
        if (role) {
            query.role = role;
        }
        
        // تصفية حسب الكلية
        if (faculty) {
            query.faculty = faculty;
        }
        
        // تصفية حسب القسم
        if (department) {
            query.department = department;
        }
        
        // تصفية حسب النقاط
        if (minPoints || maxPoints) {
            query.points = {};
            if (minPoints) query.points.$gte = parseInt(minPoints);
            if (maxPoints) query.points.$lte = parseInt(maxPoints);
        }
        
        // تصفية حسب النشاط
        if (isActive !== undefined) {
            query.isActive = isActive === 'true';
        }
        
        // ترتيب النتائج
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;
        
        // التصفح
        const skip = (parseInt(page) - 1) * parseInt(limit);
        
        const users = await User.find(query)
            .select('-password')
            .sort(sortOptions)
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await User.countDocuments(query);
        
        res.json({
            success: true,
            users,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        console.error('Admin user search error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في البحث المتقدم',
            error: error.message 
        });
    }
});

// تحديث بيانات المستخدم من قبل المسؤول
app.put('/api/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { 
            fullName, 
            email, 
            phone, 
            faculty, 
            studyLevel, 
            universityId, 
            department, 
            position, 
            role, 
            points, 
            isActive 
        } = req.body;
        
        const updateData = {};
        if (fullName !== undefined) updateData.fullName = fullName;
        if (email !== undefined) updateData.email = email;
        if (phone !== undefined) updateData.phone = phone;
        if (faculty !== undefined) updateData.faculty = faculty;
        if (studyLevel !== undefined) updateData.studyLevel = studyLevel;
        if (universityId !== undefined) updateData.universityId = universityId;
        if (department !== undefined) updateData.department = department;
        if (position !== undefined) updateData.position = position;
        if (role !== undefined) updateData.role = role;
        if (points !== undefined) updateData.points = points;
        if (isActive !== undefined) updateData.isActive = isActive;
        
        const user = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'تم تحديث بيانات المستخدم بنجاح',
            user 
        });
    } catch (error) {
        console.error('Admin update user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في تحديث بيانات المستخدم',
            error: error.message 
        });
    }
});

// إنشاء حساب مستخدم جديد من قبل المسؤول
app.post('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { 
            username, 
            password, 
            fullName, 
            email, 
            phone, 
            faculty, 
            studyLevel, 
            universityId, 
            department, 
            position, 
            role 
        } = req.body;
        
        if (!username || !password || !fullName || !email || !universityId) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال جميع الحقول المطلوبة' 
            });
        }
        
        // التحقق من عدم وجود مستخدم بنفس البيانات
        const existingUser = await User.findOne({ 
            $or: [{ username }, { email }, { universityId }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                message: 'اسم المستخدم، البريد الإلكتروني أو رقم القيد موجود بالفعل' 
            });
        }
        
        // تشفير كلمة المرور
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            username,
            password: hashedPassword,
            fullName,
            email,
            phone,
            faculty: faculty || 'كلية الآداب واللغات',
            studyLevel: studyLevel || 'سنة أولى ليسانس',
            universityId,
            department,
            position,
            role: role || 'member',
            points: 0
        });
        
        await user.save();
        
        res.status(201).json({ 
            success: true,
            message: 'تم إنشاء حساب المستخدم بنجاح',
            user: {
                id: user._id,
                username: user.username,
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                department: user.department,
                position: user.position,
                points: user.points
            }
        });
    } catch (error) {
        console.error('Admin create user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء حساب المستخدم',
            error: error.message 
        });
    }
});

// حذف مستخدم (تعطيل)
app.delete('/api/admin/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        // لا نحذف المستخدم فعلياً بل نعطله
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { isActive: false },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم غير موجود' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'تم تعطيل حساب المستخدم بنجاح',
            user 
        });
    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في تعطيل حساب المستخدم',
            error: error.message 
        });
    }
});
app.get('/api/messages', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.user.id },
                { receiver: req.user.id }
            ]
        })
        .populate('sender', 'username fullName profileImage')
        .populate('receiver', 'username fullName profileImage')
        .sort({ createdAt: -1 })
        .limit(50);
        
        res.json({
            success: true,
            count: messages.length,
            messages
        });
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب الرسائل',
            error: error.message 
        });
    }
});

app.get('/api/messages/conversation/:userId', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.user.id, receiver: req.params.userId },
                { sender: req.params.userId, receiver: req.user.id }
            ]
        })
        .populate('sender', 'username fullName profileImage')
        .populate('receiver', 'username fullName profileImage')
        .sort({ createdAt: 1 });
        
        // Mark messages as read
        await Message.updateMany(
            { receiver: req.user.id, sender: req.params.userId, isRead: false },
            { isRead: true }
        );
        
        res.json({
            success: true,
            count: messages.length,
            messages
        });
    } catch (error) {
        console.error('Get conversation error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب المحادثة',
            error: error.message 
        });
    }
});

app.get('/api/messages/unread', authenticateToken, async (req, res) => {
    try {
        const unreadCount = await Message.countDocuments({
            receiver: req.user.id,
            isRead: false
        });
        
        res.json({
            success: true,
            unreadCount
        });
    } catch (error) {
        console.error('Get unread messages error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جدد الرسائل غير المقروءة',
            error: error.message 
        });
    }
});

// 5. TASK MANAGEMENT ROUTES
app.post('/api/tasks', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { title, description, assignedTo, department, priority, deadline, points } = req.body;
        
        if (!title || !assignedTo) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال عنوان المهمة والمستخدم المسند إليه' 
            });
        }
        
        // Check if assigned user exists
        const assignedUser = await User.findById(assignedTo);
        if (!assignedUser) {
            return res.status(404).json({ 
                success: false,
                message: 'المستخدم المسند إليه غير موجود' 
            });
        }
        
        const task = new Task({
            title,
            description,
            assignedBy: req.user.id,
            assignedTo,
            department: department || assignedUser.department,
            priority: priority || 'medium',
            deadline,
            points: points || 10
        });
        
        await task.save();
        
        // Populate user info
        await task.populate('assignedBy', 'username fullName profileImage');
        await task.populate('assignedTo', 'username fullName email profileImage');
        
        res.status(201).json({ 
            success: true,
            message: 'تم إنشاء المهمة بنجاح',
            task 
        });
    } catch (error) {
        console.error('Create task error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء المهمة',
            error: error.message 
        });
    }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const { status, assignedTo, department } = req.query;
        
        let filter = {};
        
        // Regular members can only see their own tasks
        if (req.user.role === 'member') {
            filter.assignedTo = req.user.id;
        } else if (assignedTo) {
            filter.assignedTo = assignedTo;
        }
        
        if (status) filter.status = status;
        if (department) filter.department = department;
        
        const tasks = await Task.find(filter)
            .populate('assignedBy', 'username fullName profileImage')
            .populate('assignedTo', 'username fullName email profileImage')
            .sort({ deadline: 1, createdAt: -1 });
        
        res.json({
            success: true,
            count: tasks.length,
            tasks
        });
    } catch (error) {
        console.error('Get tasks error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب المهام',
            error: error.message 
        });
    }
});

app.get('/api/tasks/my-tasks', authenticateToken, async (req, res) => {
    try {
        const tasks = await Task.find({ assignedTo: req.user.id })
            .populate('assignedBy', 'username fullName profileImage')
            .sort({ deadline: 1, createdAt: -1 });
        
        res.json({
            success: true,
            count: tasks.length,
            tasks
        });
    } catch (error) {
        console.error('Get my tasks error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب مهامك',
            error: error.message 
        });
    }
});

app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const { status, feedback, rating } = req.body;
        
        const task = await Task.findById(req.params.id)
            .populate('assignedBy', 'username fullName')
            .populate('assignedTo', 'username fullName');
        
        if (!task) {
            return res.status(404).json({ 
                success: false,
                message: 'المهمة غير موجودة' 
            });
        }
        
        // Check permissions
        if (task.assignedTo._id.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false,
                message: 'غير مصرح لك بتعديل هذه المهمة' 
            });
        }
        
        const updateData = {};
        if (status) {
            updateData.status = status;
            if (status === 'completed') {
                updateData.completedAt = new Date();
            }
        }
        if (feedback && req.user.role === 'admin') {
            updateData.feedback = feedback;
        }
        if (rating && req.user.role === 'admin') {
            updateData.rating = rating;
        }
        
        const updatedTask = await Task.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        )
        .populate('assignedBy', 'username fullName profileImage')
        .populate('assignedTo', 'username fullName email profileImage');
        
        // Award points if task is completed
        if (status === 'completed' && task.status !== 'completed') {
            await User.findByIdAndUpdate(task.assignedTo, {
                $inc: { points: task.points }
            });
        }
        
        res.json({ 
            success: true,
            message: 'تم تحديث المهمة بنجاح',
            task: updatedTask 
        });
    } catch (error) {
        console.error('Update task error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في تحديث المهمة',
            error: error.message 
        });
    }
});

// 6. ACTIVITY MANAGEMENT ROUTES
app.post('/api/activities', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { title, description, type, department, location, startDate, endDate, maxParticipants, points } = req.body;
        
        if (!title || !startDate || !endDate) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال العنوان وتاريخ البداية والنهاية' 
            });
        }
        
        const activity = new Activity({
            title,
            description,
            type: type || 'meeting',
            organizer: req.user.id,
            department: department || 'عام',
            location,
            startDate: new Date(startDate),
            endDate: new Date(endDate),
            maxParticipants,
            points: points || 20,
            status: 'planned'
        });
        
        await activity.save();
        
        await activity.populate('organizer', 'username fullName profileImage');
        
        res.status(201).json({ 
            success: true,
            message: 'تم إنشاء النشاط بنجاح',
            activity 
        });
    } catch (error) {
        console.error('Create activity error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء النشاط',
            error: error.message 
        });
    }
});

app.get('/api/activities', authenticateToken, async (req, res) => {
    try {
        const { type, status, department } = req.query;
        
        let filter = {};
        if (type) filter.type = type;
        if (status) filter.status = status;
        if (department) filter.department = department;
        
        const activities = await Activity.find(filter)
            .populate('organizer', 'username fullName profileImage')
            .populate('participants', 'username fullName profileImage')
            .sort({ startDate: 1, createdAt: -1 });
        
        res.json({
            success: true,
            count: activities.length,
            activities
        });
    } catch (error) {
        console.error('Get activities error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جلب الأنشطة',
            error: error.message 
        });
    }
});

app.get('/api/activities/upcoming', authenticateToken, async (req, res) => {
    try {
        const activities = await Activity.find({
            startDate: { $gte: new Date() },
            status: 'planned'
        })
        .populate('organizer', 'username fullName profileImage')
        .populate('participants', 'username fullName profileImage')
        .sort({ startDate: 1 })
        .limit(10);
        
        res.json({
            success: true,
            count: activities.length,
            activities
        });
    } catch (error) {
        console.error('Get upcoming activities error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جدد الأنشطة القادمة',
            error: error.message 
        });
    }
});

app.post('/api/activities/:id/join', authenticateToken, async (req, res) => {
    try {
        const activity = await Activity.findById(req.params.id);
        if (!activity) {
            return res.status(404).json({ 
                success: false,
                message: 'النشاط غير موجود' 
            });
        }
        
        // Check if activity is still open for joining
        if (activity.status !== 'planned') {
            return res.status(400).json({ 
                success: false,
                message: 'لا يمكن الانضمام إلى هذا النشاط حالياً' 
            });
        }
        
        // Check if user is already a participant
        if (activity.participants.includes(req.user.id)) {
            return res.status(400).json({ 
                success: false,
                message: 'لقد انضممت بالفعل إلى هذا النشاط' 
            });
        }
        
        // Check if activity is full
        if (activity.maxParticipants && activity.participants.length >= activity.maxParticipants) {
            return res.status(400).json({ 
                success: false,
                message: 'النشاط ممتلئ' 
            });
        }
        
        activity.participants.push(req.user.id);
        await activity.save();
        
        await activity.populate('organizer', 'username fullName profileImage');
        await activity.populate('participants', 'username fullName profileImage');
        
        res.json({ 
            success: true,
            message: 'تم الانضمام إلى النشاط بنجاح',
            activity 
        });
    } catch (error) {
        console.error('Join activity error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في الانضمام إلى النشاط',
            error: error.message 
        });
    }
});

// 7. DASHBOARD STATISTICS
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ isActive: true });
        const totalTasks = await Task.countDocuments();
        const totalActivities = await Activity.countDocuments();
        const pendingTasks = await Task.countDocuments({ status: 'pending' });
        const upcomingActivities = await Activity.countDocuments({ 
            startDate: { $gte: new Date() },
            status: 'planned'
        });
        
        // User's own stats
        const myTasks = await Task.countDocuments({ assignedTo: req.user.id });
        const myCompletedTasks = await Task.countDocuments({ 
            assignedTo: req.user.id, 
            status: 'completed' 
        });
        const myActivities = await Activity.countDocuments({ participants: req.user.id });
        
        // Leaderboard
        const leaderboard = await User.find({ isActive: true })
            .select('username fullName points profileImage faculty department')
            .sort({ points: -1 })
            .limit(10);
        
        // Recent activities
        const recentActivities = await Activity.find()
            .populate('organizer', 'username fullName profileImage')
            .sort({ startDate: -1 })
            .limit(5);
        
        res.json({
            success: true,
            stats: {
                totalUsers,
                totalTasks,
                totalActivities,
                pendingTasks,
                upcomingActivities,
                myTasks,
                myCompletedTasks,
                myActivities
            },
            leaderboard,
            recentActivities
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جدد إحصائيات لوحة التحكم',
            error: error.message 
        });
    }
});

// 8. DEPARTMENT MANAGEMENT ROUTES
app.post('/api/departments', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { name, description, head } = req.body;
        
        if (!name) {
            return res.status(400).json({ 
                success: false,
                message: 'يرجى إدخال اسم القسم' 
            });
        }
        
        // Check if department already exists
        const existingDept = await Department.findOne({ name });
        if (existingDept) {
            return res.status(400).json({ 
                success: false,
                message: 'القسم موجود بالفعل' 
            });
        }
        
        const department = new Department({
            name,
            description,
            head
        });
        
        await department.save();
        
        res.status(201).json({ 
            success: true,
            message: 'تم إنشاء القسم بنجاح',
            department 
        });
    } catch (error) {
        console.error('Create department error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء القسم',
            error: error.message 
        });
    }
});

app.get('/api/departments', authenticateToken, async (req, res) => {
    try {
        const departments = await Department.find()
            .populate('head', 'username fullName profileImage')
            .populate('members', 'username fullName profileImage');
        res.json({
            success: true,
            count: departments.length,
            departments
        });
    } catch (error) {
        console.error('Get departments error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في جدد الأقسام',
            error: error.message 
        });
    }
});

// 9. UPLOAD ROUTE
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false,
                message: 'لم يتم رفع أي ملف' 
            });
        }
        
        res.json({
            success: true,
            message: 'تم رفع الملف بنجاح',
            file: {
                filename: req.file.filename,
                originalname: req.file.originalname,
                path: `/uploads/${req.file.filename}`,
                size: req.file.size,
                mimetype: req.file.mimetype
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في رفع الملف',
            error: error.message 
        });
    }
});

// 10. SEARCH FUNCTIONALITY
app.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 2) {
            return res.json({ 
                success: true,
                users: [], 
                tasks: [], 
                activities: [] 
            });
        }
        
        // Search users
        const users = await User.find({
            $or: [
                { username: { $regex: query, $options: 'i' } },
                { fullName: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } }
            ],
            isActive: true
        }).select('username fullName email profileImage role department faculty').limit(10);
        
        // Search tasks
        const tasks = await Task.find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { description: { $regex: query, $options: 'i' } }
            ]
        })
        .populate('assignedBy', 'username fullName profileImage')
        .populate('assignedTo', 'username fullName profileImage')
        .limit(10);
        
        // Search activities
        const activities = await Activity.find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { description: { $regex: query, $options: 'i' } }
            ]
        })
        .populate('organizer', 'username fullName profileImage')
        .limit(10);
        
        res.json({ 
            success: true,
            users, 
            tasks, 
            activities 
        });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في البحث',
            error: error.message 
        });
    }
});

// 11. INITIAL ADMIN CREATION (One-time setup)
app.post('/api/setup/admin', async (req, res) => {
    try {
        // Check if admin already exists
        const adminExists = await User.findOne({ role: 'admin' });
        if (adminExists) {
            return res.status(400).json({ 
                success: false,
                message: 'مسؤول النظام موجود بالفعل' 
            });
        }
        
        const { username, password, fullName, email } = req.body;
        
        if (!username || !password || !fullName || !email) {
            return res.status(400).json({ 
                success: false,
                message: 'جميع الحقول مطلوبة' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create admin user
        const admin = new User({
            username,
            password: hashedPassword,
            fullName,
            email,
            universityId: 'ADMIN001',
            faculty: 'إدارة النظام',
            studyLevel: 'مسؤول',
            role: 'admin',
            points: 1000
        });
        
        await admin.save();
        
        res.status(201).json({ 
            success: true,
            message: 'تم إنشاء مسؤول النظام بنجاح',
            admin: {
                id: admin._id,
                username: admin.username,
                fullName: admin.fullName,
                email: admin.email,
                role: admin.role
            }
        });
    } catch (error) {
        console.error('Setup admin error:', error);
        res.status(500).json({ 
            success: false,
            message: 'خطأ في إنشاء مسؤول النظام',
            error: error.message 
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ 
            success: false,
            message: 'خطأ في رفع الملف',
            error: err.message 
        });
    }
    
    res.status(500).json({ 
        success: false,
        message: 'خطأ غير متوقع في السيرفر',
        error: err.message 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        success: false,
        message: 'الصفحة غير موجودة',
        path: req.originalUrl 
    });
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
    console.log('📁 Created uploads directory');
}

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 API Base URL: http://localhost:${PORT}`);
    console.log(`📁 Uploads directory: ${__dirname}/uploads`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET ? 'Set' : 'Using default'}`);
});


  
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
  });
  

  

  
  // route to admin page

