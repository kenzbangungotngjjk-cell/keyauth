const db = require('../database/db');
const bcrypt = require('bcrypt');

async function initDatabase() {
    console.log('Initializing database...');

    try {
        // Create default admin
        const adminUsername = process.env.ADMIN_USERNAME || 'Alvin';
        const adminPassword = process.env.ADMIN_PASSWORD || 'yumieee123';
        const hashedPassword = await bcrypt.hash(adminPassword, 10);

        // Check if admin exists
        const existingAdmin = await db.get('SELECT * FROM admins WHERE username = ?', [adminUsername]);

        if (!existingAdmin) {
            await db.run(
                'INSERT INTO admins (username, password, role) VALUES (?, ?, ?)',
                [adminUsername, hashedPassword, 'superadmin']
            );
            console.log('✓ Default admin created');
        } else {
            console.log('✓ Admin already exists');
        }

        // Create some sample data for testing
        console.log('\nCreating sample data...');

        // Sample user
        const sampleUser = await db.get('SELECT * FROM users WHERE username = ?', ['testuser']);
        if (!sampleUser) {
            const userPassword = await bcrypt.hash('password123', 10);
            const userId = await db.run(
                'INSERT INTO users (username, password, email, hwid) VALUES (?, ?, ?, ?)',
                ['testuser', userPassword, 'test@example.com', 'TEST-HWID-12345']
            );
            console.log('✓ Sample user created');

            // Sample subscription for test user
            await db.run(
                'INSERT INTO subscriptions (user_id, subscription_name, expiry_date) VALUES (?, ?, datetime("now", "+30 days"))',
                [userId.id, 'Premium']
            );
            console.log('✓ Sample subscription created');
        }

        // Sample licenses
        const existingLicenses = await db.get('SELECT COUNT(*) as count FROM licenses');
        if (existingLicenses.count === 0) {
            const licenseTypes = ['Basic', 'Premium', 'Enterprise'];
            for (let i = 0; i < 10; i++) {
                const licenseKey = generateLicenseKey();
                const type = licenseTypes[Math.floor(Math.random() * licenseTypes.length)];
                await db.run(
                    'INSERT INTO licenses (license_key, subscription_type, duration_days) VALUES (?, ?, ?)',
                    [licenseKey, type, 30]
                );
            }
            console.log('✓ Sample licenses created');
        }

        console.log('\n✅ Database initialization complete!');
        console.log('\n📝 Login credentials:');
        console.log(`   Username: ${adminUsername}`);
        console.log(`   Password: ${adminPassword}`);
        console.log('\n⚠️  Please change the default password after first login!');

        process.exit(0);
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    }
}

function generateLicenseKey() {
    const crypto = require('crypto');
    const segments = 4;
    const segmentLength = 5;
    let key = '';

    for (let i = 0; i < segments; i++) {
        const segment = crypto.randomBytes(segmentLength)
            .toString('hex')
            .toUpperCase()
            .substring(0, segmentLength);
        key += segment;
        if (i < segments - 1) key += '-';
    }

    return key;
}

initDatabase();
