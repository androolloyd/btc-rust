//! Controlled acceptance fixture edits only; never called by node startup.
//! Removes only new ExEx records from a stopped, genuinely validated store to
//! reproduce the previous layout. Actual chain/body/coin/stage records remain.
use redb::{ReadableTable, TableDefinition};
fn main() -> eyre::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    eyre::ensure!(
        args.len() == 3,
        "usage: exex_fixture strip|corrupt|digest PATH"
    );
    let db = redb::Database::create(&args[2])?;
    if args[1] == "digest" {
        use sha2::{Digest, Sha256};
        let read = db.begin_read()?;
        let mut digest = Sha256::new();
        for name in ["ExExJournalV1", "ExExStatesV1"] {
            let table = read.open_table(TableDefinition::<&[u8], &[u8]>::new(name))?;
            for row in table.iter()? {
                let (k, v) = row?;
                digest.update(k.value());
                digest.update(v.value());
            }
        }
        let table = read.open_table(TableDefinition::<&str, &[u8]>::new("Meta"))?;
        for row in table.iter()? {
            let (k, v) = row?;
            digest.update(k.value().as_bytes());
            digest.update(v.value());
        }
        println!("{:x}", digest.finalize());
        return Ok(());
    }
    let write = db.begin_write()?;
    match args[1].as_str() {
        "strip" => {
            for name in ["ExExJournalV1", "ExExStatesV1"] {
                write.delete_table(TableDefinition::<&[u8], &[u8]>::new(name))?;
            }
            let mut table = write.open_table(TableDefinition::<&str, &[u8]>::new("Meta"))?;
            table.remove("validated_exex_v1")?;
        }
        "corrupt" => {
            let mut table =
                write.open_table(TableDefinition::<&[u8], &[u8]>::new("ExExJournalV1"))?;
            let key = 1u64.to_be_bytes();
            let value = table
                .get(key.as_slice())?
                .ok_or_else(|| eyre::eyre!("actual event missing"))?
                .value()
                .to_vec();
            let mut damaged = value;
            damaged[21] ^= 1;
            table.insert(key.as_slice(), damaged.as_slice())?;
        }
        _ => eyre::bail!("unknown controlled fixture mode"),
    }
    write.commit()?;
    Ok(())
}
