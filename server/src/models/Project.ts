import { Schema, model } from 'mongoose';

// This interface ensures type-safety across your backend
interface IProject {
  title: string;
  description: string;
  tech: string[];
  link: string;
  image?: string; // Optional field
}

const projectSchema = new Schema<IProject>({
  title: { type: String, required: true },
  description: { type: String, required: true },
  tech: { type: [String], default: [] },
  link: { type: String, default: '#' },
  image: { type: String }
});

export const Project = model<IProject>('Project', projectSchema);