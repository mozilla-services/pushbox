CREATE TABLE if not exists pushboxv1 (
    user_id Varchar(200) Not Null,
    device_id Varchar(200),
    data Blob,
    idx BigInt Auto_Increment,
    ttl BigInt,
    Primary Key(idx)
);
Create Index user_id_idx on pushboxv1 (user_id);
Create Index full_idx on pushboxv1 (user_id, device_id);
