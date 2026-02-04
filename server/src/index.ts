import express, { Request, Response } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
// Use the model we created earlier to keep things clean
import { Project } from './models/Project'; 
import { Experience } from './models/Experience';

dotenv.config();

const app = express();

// Senior Tip: Restrict CORS for better security (VAPT mindset)
app.use(cors({
  origin: 'http://localhost:5173', // Only allow your Vite frontend
  methods: ['GET']
}));

app.use(express.json());

// API Health Check (Professional standard)
app.get('/api/health', (req, res) => res.send('System Operational [cite: 11]'));

// ROUTES
app.get('/api/projects', async (req: Request, res: Response) => {
  try {
    // Fetching your real CV projects: C-Pay, LifeFin, Bhaswara [cite: 15, 17, 20]
    const projects = await Project.find();
    res.json(projects);
  } catch (err) {
    res.status(500).json({ message: "Database Error" });
  }
});

app.get('/api/experience', async (req: Request, res: Response) => {
  try {
    const experiences = await Experience.find();
    res.json(experiences);
  } catch (err) {
    res.status(500).json({ message: "Error fetching experience" });
  }
});

const MONGO_URI = process.env.MONGO_URI || "";

mongoose.connect(MONGO_URI)
  .then(() => console.log('🛡️ Security-Verified DB Connection Active'))
  .catch(err => console.error('❌ Connection Failed:', err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Adnan's Portfolio API: http://localhost:${PORT}`));