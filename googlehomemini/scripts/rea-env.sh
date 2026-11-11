# Source this to get REA's tool paths in the current shell: . scripts/rea-env.sh
[ -f "$HOME/.config/rea/env.sh" ] && . "$HOME/.config/rea/env.sh"
export REA_INVESTIGATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
