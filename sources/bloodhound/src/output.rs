use std::io::{Error, Write};

use crate::results::ReportResults;

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait ReportWriter {
    fn write(&self, report: &ReportResults, output: &mut dyn Write) -> Result<(), Error>;
}

pub struct TextReportWriter {}

impl ReportWriter for TextReportWriter {
    /// Writes a text formatted report to the provided output destination.
    fn write(&self, report: &ReportResults, output: &mut dyn Write) -> Result<(), Error> {
        if let Some(name) = &report.metadata.name {
            writeln!(output, "Benchmark name:  {}", name)?;
        }
        if let Some(version) = &report.metadata.version {
            writeln!(output, "Version:         {}", version)?;
        }
        if let Some(url) = &report.metadata.url {
            writeln!(output, "Reference:       {}", url)?;
        }
        writeln!(output, "Benchmark level: {}", report.level)?;
        writeln!(output, "Start time:      {}", report.timestamp)?;
        writeln!(output)?;

        for test_result in report.results.values() {
            writeln!(
                output,
                "[{}] {:9} {} ({})",
                test_result.result.status,
                test_result.metadata.id,
                test_result.metadata.title,
                test_result.metadata.mode
            )?;
        }

        writeln!(output)?;
        writeln!(output, "Passed:          {}", report.passed)?;
        writeln!(output, "Failed:          {}", report.failed)?;
        writeln!(output, "Skipped:         {}", report.skipped)?;
        writeln!(output, "Total checks:    {}", report.total)?;
        writeln!(output)?;
        writeln!(output, "Compliance check result: {}", report.status)
    }
}

pub struct JsonReportWriter {}

impl ReportWriter for JsonReportWriter {
    /// Writes a json formatted report to the provided output destination.
    fn write(&self, report: &ReportResults, output: &mut dyn Write) -> Result<(), Error> {
        let json = serde_json::to_string(&report).unwrap_or_default();
        writeln!(output, "{}", json)
    }
}
