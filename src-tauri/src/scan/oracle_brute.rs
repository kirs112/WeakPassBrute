// use std::thread;
// use r2d2_oracle::{r2d2, OracleConnectionManager};


// #[tokio::test]
// async fn test_connetct() -> Result<(),Box<dyn std::error::Error>> {
//     let manager = OracleConnectionManager::new("system", "oracle", "localhost");
//     let pool = r2d2::Pool::builder()
//         .max_size(15)
//         .build(manager)
//         .unwrap();

// for _ in 0..20 {
//     let pool = pool.clone();
//     thread::spawn(move || {
//         let conn = pool.get().unwrap();

//         // use the connection
//         // it will be returned to the pool when it falls out of scope.
//     });
// }
//     Ok(())
// }