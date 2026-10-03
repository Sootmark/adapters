//! Print timeline summaries for an event log:
//! `cargo run -p adapters --example summaries -- <file.evtx> [event id]`.

use model::adapter::{Adapter, Collected, Input};
use model::EvidenceId;
use sootmark_adapters::evtx::EvtxAdapter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: summaries <file.evtx> [event id]")?;
    let wanted: Option<u32> = args.next().map(|id| id.parse()).transpose()?;
    let bytes = std::fs::read(&path)?;
    let input = Input {
        evidence: EvidenceId::of_content(&bytes),
        name: &path,
        data: &bytes,
    };
    let mut sink = Collected::default();
    EvtxAdapter.parse(&input, &mut sink)?;
    let matching = sink
        .records
        .iter()
        .filter(|r| wanted.is_none() || r.facets.event_code == wanted);
    for record in matching.take(5) {
        println!("{}  {}", record.times[0].ts, record.summary);
    }
    Ok(())
}
