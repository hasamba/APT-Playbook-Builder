import unittest

from apt_playbook_builder import (
    Group,
    ReferenceSource,
    build_source_context,
    default_output_path,
    html_output_path,
    make_prompt,
    markdown_to_html,
    parse_group_page,
    parse_groups,
    parse_reference_source,
    render_html_report,
    sanitize_generated_text,
)


class ParserTests(unittest.TestCase):
    def test_parse_groups_from_mitre_style_links(self):
        html = """
        <table>
          <tr>
            <td><a href="/groups/G0001/">G0001</a></td>
            <td><a href="/groups/G0001/">Axiom</a></td>
            <td>Group 72</td>
            <td>A suspected Chinese cyber espionage group.</td>
          </tr>
          <tr>
            <td><a href="/groups/G0016/">G0016</a></td>
            <td><a href="/groups/G0016/">APT29</a></td>
            <td>Cozy Bear</td>
            <td>A threat group attributed to Russia's SVR.</td>
          </tr>
        </table>
        """

        groups = parse_groups(html)

        self.assertEqual([group.id for group in groups], ["G0001", "G0016"])
        self.assertEqual(groups[0].name, "Axiom")
        self.assertEqual(groups[1].name, "APT29")
        self.assertEqual(groups[1].url, "https://attack.mitre.org/groups/G0016/")

    def test_parse_group_page_extracts_techniques_and_software(self):
        group = Group(
            id="G0016",
            name="APT29",
            url="https://attack.mitre.org/groups/G0016/",
            aliases="Cozy Bear",
            description="A threat group attributed to Russia's SVR.",
        )
        html = """
        <h1>APT29</h1>
        <p>APT29 has used PowerShell and cloud credential access.</p>
        <h2>Techniques Used</h2>
        <table>
          <tr><td>T1059.001</td><td>PowerShell</td></tr>
          <tr><td>T1078</td><td>Valid Accounts</td></tr>
        </table>
        <h2>Software</h2>
        <table><tr><td>S0002</td><td>Mimikatz</td></tr></table>
        """

        page = parse_group_page(group, html)

        self.assertIn("T1059.001", page.techniques)
        self.assertIn("T1078", page.techniques)
        self.assertIn("S0002", page.software)

    def test_sanitize_generated_text_collapses_pathological_spacing(self):
        content = "## Title\n\n\n\n| A | B                                      C |\nNormal   text"

        cleaned = sanitize_generated_text(content)

        self.assertEqual(cleaned, "## Title\n\n\n| A | B C |\nNormal text\n")

    def test_default_output_path_uses_group_name(self):
        group = Group(id="G0016", name="APT29", url="https://attack.mitre.org/groups/G0016/")

        self.assertEqual(default_output_path(group), "APT29-playbook.md")
        self.assertEqual(default_output_path(group, no_ai=True), "APT29-prompt-preview.md")

    def test_parse_reference_source_extracts_title_and_text(self):
        html = """
        <html><body>
          <h1>APT29 Investigation Report</h1>
          <p>Observed IOC: example.com and hash abc123.</p>
        </body></html>
        """

        source = parse_reference_source("https://example.test/report", html)

        self.assertEqual(source.title, "APT29 Investigation Report")
        self.assertIn("example.com", source.text)

    def test_build_source_context_includes_reference_urls(self):
        group = Group(id="G0016", name="APT29", url="https://attack.mitre.org/groups/G0016/")
        page = parse_group_page(
            group,
            "<h1>APT29</h1><p>Overview</p>",
            reference_sources=[
                ReferenceSource(
                    url="https://example.test/report",
                    title="External Report",
                    text="IOC: example.com",
                )
            ],
        )

        context = build_source_context(page)

        self.assertIn("https://example.test/report", context)
        self.assertIn("IOC: example.com", context)

    def test_prompt_requires_notebook_post_process_vql(self):
        group = Group(id="G0016", name="APT29", url="https://attack.mitre.org/groups/G0016/")
        page = parse_group_page(group, "<h1>APT29</h1><p>Overview</p>")

        prompt = make_prompt(page)

        self.assertIn("Notebook Post-Process VQL", prompt)
        self.assertIn("Velociraptor notebook", prompt)
        self.assertIn("fenced `vql` code blocks", prompt)

    def test_html_output_path_replaces_markdown_suffix(self):
        self.assertEqual(html_output_path("APT29-playbook.md"), "APT29-playbook.html")
        self.assertEqual(html_output_path("report.txt"), "report.txt.html")

    def test_markdown_to_html_preserves_vql_code_block(self):
        rendered = markdown_to_html("## Query\n\n```vql\nSELECT * FROM source()\n```")

        self.assertIn("<h2>Query</h2>", rendered)
        self.assertIn('class="language-vql"', rendered)
        self.assertIn("SELECT * FROM source()", rendered)

    def test_render_html_report_wraps_markdown_with_title(self):
        rendered = render_html_report("# APT29\n\n**Triage**", title="APT29 Playbook")

        self.assertIn("<title>APT29 Playbook</title>", rendered)
        self.assertIn("Velociraptor DFIR Playbook", rendered)
        self.assertIn("<strong>Triage</strong>", rendered)


if __name__ == "__main__":
    unittest.main()
