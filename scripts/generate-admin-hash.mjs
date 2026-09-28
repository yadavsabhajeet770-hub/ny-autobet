import bcrypt from 'bcryptjs';
const password = process.argv.slice(2).join(' ');
if (!password || password.length < 12) {
  console.error('Usage: node scripts/generate-admin-hash.mjs "your-long-admin-password"');
  process.exit(1);
}
console.log(bcrypt.hashSync(password, 12));
