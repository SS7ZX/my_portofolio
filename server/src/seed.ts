import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { Project } from './models/Project';
import { Experience } from './models/Experience';

dotenv.config();

const sampleData = [
  {
    title: "C-Pay Ecosystem",
    description: "Independently engineered a closed-loop payment system with secure transaction logic and MERN architecture[cite: 15].",
    tech: ["MongoDB", "Express", "React", "Node.js"],
    link: "https://github.com/SS7ZX"
  },
  {
    title: "LifeFin UMKM Web-App",
    description: "Architected a financial platform for MSMEs with a focus on data encryption and WCAG accessibility[cite: 12, 20].",
    tech: ["React", "Supabase", "UX Design"],
    link: "https://github.com/SS7ZX"
  },
  {
    title: "VAPT Excellence Audit",
    description: "Officially recognized by Universitas Siber Indonesia for excellence in Security System Evaluation and vulnerability mitigation[cite: 19, 38].",
    tech: ["Burp Suite", "OWASP Top 10", "Network Security"],
    link: "https://github.com/SS7ZX"
  },
  {
    title: "Bhaswara Regional Learning",
    description: "National Top 50 Finalist. A gamified regional language learning prototype[cite: 17, 18].",
    tech: ["Product Design", "Figma", "Web Dev"],
    link: "https://github.com/SS7ZX"
  }
];

const orgExperience = [
  {
    title: "Vice President (Wakil Himpunan)",
    organization: "Information Systems & Technology Student Association",
    description: "Leading strategic initiatives and coordinating departmental synergy for 3rd-semester Information Systems students[cite: 5, 32].",
    period: "2025 - Present"
  },
  {
    title: "Head of Basketball Division",
    organization: "Sports UKM (Student Activity Unit)",
    description: "Managing team logistics, training schedules, and competitive strategy for the university basketball division.",
    period: "2024 - Present"
  }
];

const seedDB = async () => {
  try {
    console.log("📡 Connecting to MongoDB...");
    // Force the script to wait for the connection
    await mongoose.connect(process.env.MONGO_URI || '');
    console.log("✅ Connection established.");

    // Clear and Seed Projects
    await Project.deleteMany({});
    await Project.insertMany(sampleData);
    console.log("📦 Projects synced.");

    // Clear and Seed Organizations (Leadership)
    await Experience.deleteMany({}); 
    await Experience.insertMany(orgExperience);
    console.log("👥 Leadership experience synced.");

    console.log("🌱 DATABASE FULLY SEEDED!");
  } catch (err) {
    console.error("❌ Critical Seed Error:", err);
  } finally {
    // Gracefully close the connection instead of just crashing out
    await mongoose.connection.close();
    process.exit();
  }
};

seedDB();