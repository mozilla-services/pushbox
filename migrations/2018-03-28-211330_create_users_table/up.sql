CREATE TABLE if not exists pushboxv1 (
    user_id Varchar(200) Not Null,
    device_id Varchar(200),
    data Blob,
    idx BigInt Auto_Increment,
    ttl BigInt,
    Primary Key(idx)
);

# testing may call apply_mutations repeatedly.
# this will only add an index if it's not already present.

DELIMITER $$
DROP PROCEDURE IF EXISTS `create_index` $$
CREATE PROCEDURE `create_index` (
    idx_name VARCHAR(64),
    cols VARCHAR(64)
)
BEGIN
    DECLARE index_exists INTEGER;

    SELECT COUNT(1) INTO index_exists
    FROM information_schema.statistics
    WHERE table_schema='pushbox'
    AND   table_name='pushboxv1'
    AND   index_name=idx_name;

    IF index_exists = 0 THEN
        SET @stmt = CONCAT('CREATE INDEX ',idx_name,' ON ',
        'pushbox.pushboxv1 (',cols,')');
        PREPARE st from @stmnt;
        EXECUTE st;
        DEALLOCATE PREPARE st;
    END IF;
END $$
DELIMITER ;

#Create Index user_id_idx on pushboxv1 (user_id);
call create_index('user_id_idx', 'user_id');
#Create Index full_idx on pushboxv1 (user_id, device_id);
call create_index('full_idx', 'user_id, device_id');
