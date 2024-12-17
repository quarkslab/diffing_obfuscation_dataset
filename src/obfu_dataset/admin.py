# built-in imports
import click
from pathlib import Path
import json
import zipfile

# third-party imports
from rclone_python import rclone
from rclone_python.hash_types import HashTypes

# local imports
from obfu_dataset import (ObfuDataset, Project, BinaryType,
                          ObPass, Obfuscator, DownloadLink, supported_passes, AVAILABLE_LEVELS)

REMOTE_NAME = "obfuscation-dataset"

PROJ_OPT = [x.value for x in Project]
EXT_BLACKLIST = [".sqlite", ".i64"]


@click.group(context_settings={'help_option_names': ['-h', '--help']})
def main():
    pass


def make_zip_name(project: Project,
                  type: BinaryType,
                  obfuscator: Obfuscator = None,
                  obpass: ObPass = None,
                  level: int = None):
    match type:
        case BinaryType.PLAIN:
            return f"{project.value}-sources.zip"
        case BinaryType.OBFUSCATED:
            return f"{project.value}_{obfuscator.value}_{obpass.value}_{level}.zip"


def get_info_remote_file(remote_path: str) -> tuple[str, int, str] | None:
    info = rclone.ls(remote_path)
    if info:
        size = info[0]['Size']
        url = rclone.link(remote_path).split(".zip")[0]+".zip"
        hash = rclone.hash(HashTypes.md5, remote_path)
        return url, size, hash
    else:
        return "https://foo", 0, "DEADBEEF"


@main.command(name="mk-links")
@click.option("-o", "--out", type=click.Path(), help="Output json file")
def mk_links(out: str):
    def to_json(entry):
        return {
            "project": entry.project.value,
            "type": entry.type.value,
            "link": entry.link,
            "size": entry.size,
            "hash": entry.hash,
            "obfuscator": entry.obfuscator.value if entry.obfuscator else None,
            "obpass": entry.obpass.value if entry.obpass else None,
            "level": entry.level if entry.level else None
        }

    d = {}
    for project in Project:
        print(f"project: {project.value}")

        # Create the source entry
        zip_name = make_zip_name(project, BinaryType.PLAIN)
        remote_path = f"{REMOTE_NAME}:{REMOTE_NAME}/{project.value}/{zip_name}"
        url, size, hash = get_info_remote_file(remote_path)

        # Create DownloadLink object
        entry = DownloadLink(project, BinaryType.PLAIN, url, size, hash)
        d[project.value] = {}
        d[project.value]['sources'] = to_json(entry)

        # Create obfuscated entries
        d[project.value]['obfuscated'] = {}
        for obfu in Obfuscator:
            d[project.value]['obfuscated'][obfu.value] = {}
            for obpass in supported_passes(obfu):
                d[project.value]['obfuscated'][obfu.value][obpass.value] = {}
                for level in AVAILABLE_LEVELS:
                    d[project.value]['obfuscated'][obfu.value][obpass.value][level] = {}
                    # Get info from remote file
                    zip_name = make_zip_name(project, BinaryType.OBFUSCATED, obfu, obpass, level)
                    remote_path = f"{REMOTE_NAME}:{REMOTE_NAME}/{project.value}/obfuscated/{obfu.value}/{zip_name}"
                    url, size, hash = get_info_remote_file(remote_path)
                    # Create DownloadLink object
                    entry = DownloadLink(project, BinaryType.OBFUSCATED, url, size, hash, obfu, obpass, level)
                    d[project.value]['obfuscated'][obfu.value][obpass.value][level] = to_json(entry)


    # Write the resulting json file
    with open(out, "w") as f:
        json.dump(d, f, indent=2)


def make_source_zip(out_file, dir) -> None:
    base = Path(dir)
    with zipfile.ZipFile(out_file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        #for root, dirs, files in base.walk():
        for file_path in base.rglob("*"):
            #file_path = root / file
            if file_path.is_file() and file_path.suffix not in EXT_BLACKLIST:
                arcname = Path("sources") / file_path.relative_to(base)
                zip_file.write(file_path, arcname)


def make_obfuscation_zip(out_file, dir) -> None:
    # dir here is an obfu pass directory
    base = Path(dir)
    rel = Path(base.name)
    with zipfile.ZipFile(out_file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in base.rglob("*"):
            #for file in files:
            #    file_path = root / file
            if file_path.is_file() and file_path.suffix not in EXT_BLACKLIST:
                arcname = rel / file_path.relative_to(base)
                zip_file.write(file_path, arcname)


@main.command(name="upload")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), default=None, help="Project to download")
@click.option("-t", "--type", type=click.Choice([x.value for x in BinaryType]), default=None, help="Type to upload")
@click.option("--override/--no-override", type=bool, is_flag=True, default=False, help="Override remote zip files in the bucket")
@click.option("--upload/--no-upload", type=bool, is_flag=True, default=True, help="Do upload zip files")
@click.argument("root", type=click.Path(exists=True))
def upload(project: str, type: str, override: bool, upload: bool, root: str):

    dataset = ObfuDataset(root)

    projects = [Project(project)] if project else list(Project)
    bin_types = [BinaryType(type)] if type else list(BinaryType)

    for proj in projects:
        if BinaryType.PLAIN in bin_types:
            # check plain
            src_dir = dataset.get_src_path(proj)
            src_zip = src_dir.parent / make_zip_name(proj, BinaryType.PLAIN)
            if not src_zip.exists():
                print(f"Create zip: {src_zip}")
                make_source_zip(src_zip, src_dir)
            remote_path = f"{REMOTE_NAME}:{REMOTE_NAME}/{proj.value}/"

            # Copy only if not present
            if upload:
                print(f"Remote copy: {src_zip}")
                rclone.copy(str(src_zip.resolve()), remote_path, ignore_existing=not override)

        if BinaryType.OBFUSCATED in bin_types:
            # check obfuscated
            for obfu in Obfuscator:
                for obpass in supported_passes(obfu):
                    for level in AVAILABLE_LEVELS:
                        obfu_dir = dataset.get_obfu_path(proj, obfu, obpass, level)
                        obpass_zip = obfu_dir.parent / make_zip_name(proj, BinaryType.OBFUSCATED, obfu, obpass, level)
                        if not obpass_zip.exists():
                            print(f"Create zip: {obpass_zip}")
                            make_obfuscation_zip(obpass_zip, obfu_dir)
                        remote_path = f"{REMOTE_NAME}:{REMOTE_NAME}/{proj.value}/obfuscated/{obfu.value}/"

                        # Copy only if not present
                        if upload:
                            print(f"Remote copy: {obpass_zip}")
                            rclone.copy(str(obpass_zip.resolve()), remote_path, ignore_existing=not override)


if __name__ == "__main__":
    main()

