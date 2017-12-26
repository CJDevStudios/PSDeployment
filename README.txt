PowerShell Deployment Module

Configuration:
Change the Package Location in the PSDeploy.cfg file.

Creating a package:
1. Create a new folder in the package location. The name of the folder will be the package name.
2. Copy source files into the folder.
3. Create a package.info file and add properties in "NAME: VALUE" format. All properties are optional.

Package.info properties:
ParentPackage [String]: The parent package. If multiple packages share similar sources, you can place the shared resources in a new "Parent" package to save disk space. Default is null.

Dependencies [String]: Any other packages that this on relies on. Default is null.

InstallAction [String]: The command to run to install the package. Default is "install.cmd"

UninstallAction [String]: The command to run to remove the package. Default is "uninstall.cmd"

InstallNeedsSources [boolean]: If the source files are needed for the install. Default is true.

UninstallNeedsSources [boolean]: If the source files are needed for the uninstall. Default is true.

RequiresMSI [boolean]: If msiexec is used for the install or uninstall. Since only 1 instance of an msi installer can run at a time, this indicates that it should wait for current installers to finish before processing this deployment. Default is true.

InstallDanger [String]: A warning to prompt before the install can run. Default is null.

UninstallDanger [String]: A warning to prompt before the uninstall can run. Default is null.