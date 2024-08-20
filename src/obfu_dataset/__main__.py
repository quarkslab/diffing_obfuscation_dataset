import click

from obfu_dataset.types import Project, Obfuscator, ObPass
from obfu_dataset.dataset import ObfuDataset

PROJ_OPT = [x.value for x in Project]
OBF_OPT = [x.value for x in Obfuscator]
PASS_OPT = [x.value for x in ObPass]


@click.group(context_settings={'help_option_names': ['-h', '--help']})
def main():
    pass


@main.command(name="ls")
def list():
    pass


@main.command(name="download-plain")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.argument("project", type=click.Choice(PROJ_OPT), nargs=-1)
def download_plain(root: str, project: tuple[str]):

    dataset = ObfuDataset(root)

    for proj in (Project(x) for x in project):
        dataset.download_plain(proj)


@main.command(name="download-obfuscated")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=True, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-op", "--obf-pass", type=click.Choice(PASS_OPT), default=None, required=False, help="Obfuscation pass to download (all if none)")
def download_obfuscated(root: str, project: tuple[str], obfuscator: str|None, obf_pass: str|None):

    dataset = ObfuDataset(root)

    for proj in (Project(x) for x in project):
        obfs = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
        for obf in obfs:
            passes = [ObPass(obf_pass) if obf_pass else list(ObPass)]
            for p in passes:
                dataset.download_obfuscated(proj, obf, p)


@main.command(name="download-all")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def download_all(root: str):
    dataset = ObfuDataset(root)
    dataset.download_all()


@main.command(name="create")
def create():
    # checker presence tigress3.1
    # checker OLLVM + version !] <== pas besoin

    # Creer source obfusquée:
    #   * tigress  <== PYTHON
    #   * ollvm

    # Printer + logger tout
    pass


@main.command(name="compile")
def compile():
    # checker presence OLLVM + version => Selectionner le bon
    # Appliquer fixup Tigress
    # Compiler source obfusquée
    #   * ollvm
    #   * gcc (pour Tigress)

    # Printer + logger tout!
    pass

@main.command(name="extract-symbols")
def extract_symbols():
    # Extract symbols with idascript
    # Printer + log everything
    pass

@main.command(name="strip")
def strip():
    # Execute strip
    pass

@main.command(name="export")
def export():
    # Export both with Quokka & Binexport
    pass



if __name__ == "__main__":
    main()
