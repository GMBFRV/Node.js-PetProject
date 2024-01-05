require('dotenv').config();

module.exports = {
    development: {
        dialect: 'postgres',
        database: process.env.DB_DATABASE || 'nodedb_smzt',
        dialectOptions: {
            ssl: {
                rejectUnauthorized: false, // для работы с самоподписанными сертификатами Render.com
            },
        },
        ssl: true,
        host: process.env.DB_HOSTNAME || 'dpg-cmbshfv109ks73aetn80-a.oregon-postgres.render.com',
        port: process.env.DB_PORT || 5432,
        username: process.env.DB_USERNAME || 'user',
        password: process.env.DB_PASSWORD || 'G13GChTWsiut9OCIRFyCdgQDZkWF6LLV',
    },
};
