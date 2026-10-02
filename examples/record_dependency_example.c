/*
 * 记录指定对象对当前正在创建的扩展（Extension）的依赖关系。
 *
 * object:
 *     需要加入当前扩展的数据库对象。
 *
 * isReplace:
 *     表示当前操作是否属于替换已有对象。
 *     如果为 true，需要先检查该对象是否已经属于某个扩展，
 *     避免一个对象同时成为多个扩展的成员。
 */
recordDependencyOnCurrentExtension(const ObjectAddress *object, bool isReplace)
{
    /*
     * 扩展成员只能是完整对象，
     * 不允许只把对象的某个子对象作为扩展成员。
     */
    Assert(object->objectSubId == 0);

    /* 只有当前正处于 CREATE EXTENSION 等扩展创建流程时才需要处理 */
    if (creating_extension)
    {
        ObjectAddress extension;

        /*
         * 如果当前操作是在替换已有对象，
         * 需要检查该对象之前是否已经属于某个扩展。
         */
        if (isReplace)
        {
            Oid oldext;

            /* 查询该对象当前所属的扩展 */
            oldext = getExtensionOfObject(object->classId, object->objectId);

            /* 如果已经属于某个扩展 */
            if (OidIsValid(oldext))
            {
                /*
                 * 如果它本来就属于当前正在创建的扩展，
                 * 那么依赖关系已经存在，无需重复记录。
                 */
                if (oldext == CurrentExtensionObject)
                    return;

                /*
                 * 如果它属于其他扩展，则拒绝当前操作。
                 * 一个对象不能同时作为两个不同扩展的成员。
                 */
                ereport(ERROR,
                        (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                         errmsg("%s is already a member of extension \"%s\"",
                                getObjectDescription(object, false),
                                get_extension_name(oldext))));
            }
        }

        /*
         * 构造当前扩展的 ObjectAddress，
         * 表示依赖目标是 CurrentExtensionObject。
         */
        extension.classId = ExtensionRelationId;
        extension.objectId = CurrentExtensionObject;
        extension.objectSubId = 0;

        /*
         * 记录 object 对当前扩展的 DEPENDENCY_EXTENSION 依赖。
         *
         * 建立该依赖后，PostgreSQL 会把 object 视为扩展的一部分，
         * 扩展的删除、管理等操作会考虑这个成员关系。
         */
        recordDependencyOn(object, &extension, DEPENDENCY_EXTENSION);
    }
}