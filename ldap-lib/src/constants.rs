/// Specify which information should be provided for groups.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum GroupStrategy {
    /// Do not include any group information.
    NoGroupInfo,
    /// Include group information including direct members (i.e. users) of each group.
    DirectMembers,
    /// Include group information including direct members (i.e. users)
    /// and members of all subgroups, recursively, of each group.
    SubgroupMembers,
}
