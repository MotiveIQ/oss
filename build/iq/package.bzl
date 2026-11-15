"""Bazel declarations for packages installable with `iq install`."""

load("@rules_pkg//pkg:install.bzl", "pkg_install")
load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_files")

def _label_string(target):
    value = str(target.label)
    if value.startswith("@@//"):
        return value[2:]
    return value

def _iq_pkg_descriptor_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".iq_pkg.json")
    descriptor = {
        "schema_version": 1,
        "package": ctx.attr.package,
        "description": ctx.attr.description,
        "install_name": ctx.attr.install_name,
        "installer": _label_string(ctx.attr.installer),
        "paths": ["bin/%s" % ctx.attr.install_name] + ctx.attr.runtime_paths,
    }
    ctx.actions.write(out, json.encode(descriptor) + "\n")
    return [DefaultInfo(files = depset([out]))]

_iq_pkg_descriptor = rule(
    implementation = _iq_pkg_descriptor_impl,
    attrs = {
        "description": attr.string(),
        "install_name": attr.string(mandatory = True),
        "installer": attr.label(mandatory = True),
        "package": attr.string(mandatory = True),
        "runtime_paths": attr.string_list(),
    },
)

def _validate_name(value, attribute):
    if not value:
        fail("iq_pkg %s must not be empty" % attribute)
    if "/" in value or "\\" in value or value in [".", ".."]:
        fail("iq_pkg %s must be a single path component, got %r" % (attribute, value))

def iq_pkg(
        name,
        package,
        binary,
        install_name = None,
        description = "",
        runtime_files = {},
        installer = None,
        tags = [],
        visibility = ["//visibility:public"]):
    """Declare an opinionated user package installable with `iq install`.

    `iq install` always installs packages beneath `~/.local`. Executables are
    mapped to `bin/<install_name>` with mode 0755. Optional runtime_files map
    executable labels to paths beneath the same prefix. An optional installer
    wrapper may perform package-specific setup; the underlying pkg_install target
    is then named <name>_payload_installer and the descriptor points at the wrapper.
    """
    install_name = install_name or package
    _validate_name(package, "package")
    _validate_name(install_name, "install_name")

    files_name = name + "_files"
    installer_name = name + ("_payload_installer" if installer else "_installer")

    pkg_files(
        name = files_name,
        srcs = [binary],
        attributes = pkg_attributes(mode = "0755"),
        prefix = "bin",
        renames = {binary: install_name},
        visibility = ["//visibility:private"],
    )

    install_files = [":" + files_name]
    if runtime_files:
        for path in runtime_files.values():
            if path.startswith("/") or "\\" in path or any([part in ["", ".", ".."] for part in path.split("/")]):
                fail("iq_pkg runtime_files paths must be relative, got %r" % path)
        runtime_name = name + "_runtime_files"
        pkg_files(
            name = runtime_name,
            srcs = runtime_files.keys(),
            attributes = pkg_attributes(mode = "0755"),
            renames = runtime_files,
            visibility = ["//visibility:private"],
        )
        install_files.append(":" + runtime_name)

    pkg_install(
        name = installer_name,
        srcs = install_files,
        visibility = visibility,
    )

    _iq_pkg_descriptor(
        name = name,
        package = package,
        description = description,
        install_name = install_name,
        installer = installer or ":" + installer_name,
        runtime_paths = sorted(runtime_files.values()),
        tags = tags + [
            "iq_pkg",
            "iq_pkg_name=%s" % package,
        ],
        visibility = visibility,
    )
