table! {
    pushboxv1 (user_id, device_id, service) {
        user_id -> Varchar,
        device_id -> Varchar,
        service -> Varchar,
        data -> Binary,
        idx -> Bigint,
        ttl -> Bigint,
    }
}
