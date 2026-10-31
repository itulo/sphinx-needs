import json
from pathlib import Path

import pytest
from syrupy.filters import props

from sphinx_needs.config import NeedsSphinxConfig
from sphinx_needs.data import SphinxNeedsData
from sphinx_needs.needsfile import NeedsOutputPathError, _checked_json_path
from sphinx_needs_testkit import build_warnings


@pytest.mark.parametrize(
    "test_app",
    [{"buildername": "needs_id", "srcdir": "doc_test/doc_needs_builder"}],
    indirect=True,
)
def test_doc_needs_id_builder(test_app, snapshot):
    app = test_app
    app.build()
    data = SphinxNeedsData(app.env)
    needs_config = NeedsSphinxConfig(app.config)
    needs_id_path = Path(app.outdir, needs_config.build_json_per_id_path)
    data = {
        path.name: json.loads(path.read_text()) for path in needs_id_path.glob("*.json")
    }
    assert data == snapshot(exclude=props("created", "project", "creator"))


@pytest.mark.parametrize(
    "file_name",
    [
        "",
        ".",
        "..",
        "../pwned.json",
        "..\\..\\pwned.json",
        "/tmp/pwned.json",
        "C:/pwned.json",
        "C:pwned.json",
        "foo/bar.json",
        "foo\\bar.json",
        "\\\\server\\share\\pwned.json",
        "a\x00b.json",
    ],
)
def test_checked_json_path_rejects_a_name_that_is_not_one_file(
    tmp_path: Path, file_name: str
) -> None:
    """A need id is used as this file name. Separators and ``..`` must not pass on
    either platform: the suite runs on POSIX, where a backslash is not a separator."""
    directory = tmp_path / "needs_id"
    directory.mkdir()
    with pytest.raises(NeedsOutputPathError):
        _checked_json_path(str(directory), file_name)


@pytest.mark.parametrize(
    "file_name",
    [
        "REQ_SAFE.json",
        "EXT.SAFE-1.json",
        "..json",
        "...json",
        ".hidden.json",
        "a name.json",
        "需求.json",
    ],
)
def test_checked_json_path_accepts_a_single_file_name(
    tmp_path: Path, file_name: str
) -> None:
    directory = tmp_path / "needs_id"
    directory.mkdir()
    assert Path(_checked_json_path(str(directory), file_name)) == directory / file_name


def test_checked_json_path_refuses_a_symlink_that_leaves_the_directory(
    tmp_path: Path,
) -> None:
    """A name with no separator still leaves the directory when it is a symlink."""
    directory = tmp_path / "needs_id"
    outside = tmp_path / "outside"
    directory.mkdir()
    outside.mkdir()
    (directory / "REQ_SAFE.json").symlink_to(outside / "pwned.json")
    with pytest.raises(NeedsOutputPathError):
        _checked_json_path(str(directory), "REQ_SAFE.json")
    assert not (outside / "pwned.json").exists()


_PER_ID_CONF = """\
extensions = ["sphinx_needs"]
needs_external_needs = [{
    "base_url": "http://example.com/docs",
    "json_path": "needs.json",
}]
needs_builder_filter = ""
"""

_PER_ID_INDEX = """\
Title
=====

.. req:: Safe local
   :id: REQ_SAFE

.. req:: Id with a path
   :id: ABCDE/../../pwned_local
"""


@pytest.mark.parametrize(
    "test_app",
    [
        {
            "buildername": "needs_id",
            "files": [
                ("conf.py", _PER_ID_CONF),
                ("index.rst", _PER_ID_INDEX),
            ],
        }
    ],
    indirect=True,
)
def test_per_id_json_stays_inside_the_output_directory(test_app) -> None:
    """An id the default ``needs_id_regex`` accepts, and ids from an external
    needs.json (which that regex never sees), are not written outside the per-id
    directory. The needs themselves stay loaded."""
    app = test_app
    # Beside the source directory, not under it: a path under ``srcdir`` is rewritten
    # to ``<srcdir>/`` in the warning text, which would hide the id the builder was given.
    outside = Path(app.srcdir).resolve().parent / "outside"
    outside.mkdir()
    absolute_id = str(outside / "pwned")
    needs = {
        "EXT.SAFE-1": {
            "id": "EXT.SAFE-1",
            "title": "safe external",
            "type": "req",
        },
        "../ext_pwned": {
            "id": "../ext_pwned",
            "title": "relative escape",
            "type": "req",
        },
        absolute_id: {
            "id": absolute_id,
            "title": "absolute escape",
            "type": "req",
        },
    }
    (Path(app.srcdir) / "needs.json").write_text(
        json.dumps({"current_version": "1.0", "versions": {"1.0": {"needs": needs}}}),
        encoding="utf-8",
    )

    app.build()

    needs_dir = Path(app.outdir) / "needs_id"
    assert sorted(
        p.relative_to(needs_dir).as_posix() for p in needs_dir.rglob("*")
    ) == [
        "EXT.SAFE-1.json",
        "REQ_SAFE.json",
    ]
    # Where the unsanitised join would have written. Each parent exists, so a
    # missing check would have created the file rather than failed to open it.
    assert not (Path(app.outdir) / "pwned_local.json").exists()
    assert not (Path(app.outdir) / "ext_pwned.json").exists()
    assert not (outside / "pwned.json").exists()

    loaded = SphinxNeedsData(app.env).get_needs_view()
    assert set(loaded) >= {
        "REQ_SAFE",
        "ABCDE/../../pwned_local",
        "EXT.SAFE-1",
        "../ext_pwned",
        absolute_id,
    }

    skipped = (
        "is not exported to a per-id JSON file: "
        "its id is not a single file name inside the output directory [needs.json_path]"
    )
    assert build_warnings(app) == [
        f"WARNING: Need {'../ext_pwned'!r} {skipped}",
        f"WARNING: Need {absolute_id!r} {skipped}",
        "<srcdir>/index.rst:7: WARNING: Need 'ABCDE/../../pwned_local' " + skipped,
    ]
